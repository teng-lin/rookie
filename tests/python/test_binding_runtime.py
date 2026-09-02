"""Interpreter-level contracts that only the binding can break.

Nothing here re-tests a decoder. These cover what sits between CPython and the
core: whether a long extraction holds the GIL, whether a handle cancelled from
another thread is observed mid-flight, whether two extractions can run in one
interpreter at once, whether the logging bridge stays inside the package's
logger, and whether Unicode survives both the value path and the path path.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Iterable, Iterator, Optional

import rookie_cookies

# Starting size for `_sized_store`, which grows it until one extraction is
# long enough to observe. Every row is already expired, so the work happens in
# Rust without materializing a large Python list on the way out.
_LARGE_ROWS = 100_000
# How long an extraction must take before a thread-scheduling assertion about
# it means anything. Two OS scheduler quanta, with room to spare.
_MIN_WINDOW_SECONDS = 0.03
# Bounded so a pathologically fast machine fails loudly rather than seeding
# until it runs out of memory.
_MAX_DOUBLINGS = 3
# The heartbeat's sleep, and the unit the GIL assertion's bound is in.
_HEARTBEAT_INTERVAL = 0.001
_EXPIRED_MS = 1_000_000_000
_LIVE_MS = 4_102_444_800_000

# Set by `scripts/run-python-coverage.py` for the suite it runs against the
# wheel it just built with `-C instrument-coverage`, and by nothing else. Not
# keyed off `LLVM_PROFILE_FILE`: that only says where an instrumented binary
# would write its profile, so a developer exporting it for an unrelated
# profiling task would stand a test down against an uninstrumented wheel. Any
# future lane that instruments the extension has to set this too.
_COVERAGE_INSTRUMENTED = os.environ.get("ROOKIE_COOKIES_INSTRUMENTED") == "1"

# Only a *scaling* measurement needs this, and only the measurement -- never a
# correctness assertion. Instrumentation turns every basic block into a shared
# atomic counter increment, so N threads on one extraction path contend on the
# same counter cache lines and the parallel speedup collapses to roughly 1x:
# measured at 0.96x and 1.11x on `Python binding coverage (macos-latest)` while
# all four uninstrumented `Python build and tests (macos-latest)` jobs passed
# the same suite (issue #337). The other timing-sensitive tests in this file
# are not exposed the same way: `GilReleaseTest` asks whether another Python
# thread runs *at all* during one extraction, which counter contention inside
# that single thread does not change, and the cancellation and `_sized_store`
# timings only benefit from instrumentation making an extraction longer.
_INSTRUMENTED_SKIP_REASON = (
    "the extension under test was built with -C instrument-coverage "
    "(ROOKIE_COOKIES_INSTRUMENTED=1): LLVM's shared atomic per-block counters "
    "serialize threads running the same code, which flattens real parallelism "
    "to about 1x and would make this measurement report serialization that is "
    "not there. Everything above this point still ran and was asserted, and "
    "the bound itself is not disabled -- it is measured, and must hold, in "
    "every uninstrumented lane"
)

_UNICODE_DOMAIN = ".юникод.test"
_UNICODE_NAME = "имя"
_UNICODE_VALUE = "значение-\U0001f36a"
_UNICODE_DIRECTORY = "профиль-\U0001f36a"

# pyo3-log caches each Rust target's effective level the first time that target
# logs, and a later `setLevel` does not invalidate the cache. Raising the level
# here -- at import, before any test in any module has run an extraction -- is
# what makes `LoggingBridgeTest` able to observe records at all. Nothing is
# printed as a side effect: these propagate to a root logger with no handler,
# and `logging.lastResort` only emits WARNING and above.
logging.getLogger("rookie_cookies").setLevel(logging.DEBUG)

_MOZ_SCHEMA = """
CREATE TABLE moz_cookies (
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  isSecure INTEGER NOT NULL,
  expiry INTEGER NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  isHttpOnly INTEGER NOT NULL,
  sameSite INTEGER NOT NULL
)
"""


def _seed_gecko(path: Path, rows: Iterable[tuple[str, int, str, str]]) -> Path:
    connection = sqlite3.connect(str(path))
    try:
        connection.execute("PRAGMA user_version = 16")
        connection.execute(_MOZ_SCHEMA)
        connection.executemany(
            "INSERT INTO moz_cookies VALUES (?, '/', 0, ?, ?, ?, 0, 0)", rows
        )
        connection.commit()
    finally:
        connection.close()
    return path


def _expired_rows(count: int) -> Iterator[tuple[str, int, str, str]]:
    # A generator, not a list: at the sizes `_sized_store` can reach, the
    # intermediate list costs more memory than the database it produces.
    for index in range(count):
        yield (f".host{index % 977}.test", _EXPIRED_MS, f"name{index}", f"value{index}")


def _seed_large(path: Path, rows: int = _LARGE_ROWS) -> Path:
    return _seed_gecko(path, _expired_rows(rows))


def _sized_store(directory: Path) -> tuple[Path, float]:
    """A store one extraction of which takes at least `_MIN_WINDOW_SECONDS`.

    A fixed row count cannot serve both build profiles: these tests were
    written against a debug wheel where 100k rows take a few hundred
    milliseconds, while the release wheel CI installs is several times faster,
    and a window shorter than a scheduler quantum makes any assertion about
    another thread meaningless. Doubling until the extraction is long enough
    makes the tests independent of the build profile and of the machine.
    """
    rows = _LARGE_ROWS
    for attempt in range(_MAX_DOUBLINGS + 1):
        database = _seed_large(directory / f"cookies-{attempt}.sqlite", rows)
        started = time.perf_counter()
        rookie_cookies.from_path(str(database))
        elapsed = time.perf_counter() - started
        if elapsed >= _MIN_WINDOW_SECONDS:
            return database, elapsed
        rows *= 2
    raise AssertionError(
        f"{rows // 2} expired rows still extract in under "
        f"{_MIN_WINDOW_SECONDS}s; raise _MAX_DOUBLINGS"
    )


class _Heartbeat:
    """A Python thread that can only tick while some other thread frees the GIL."""

    def __init__(self, interval: float = _HEARTBEAT_INTERVAL) -> None:
        self.ticks = 0
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.ticks += 1
            time.sleep(self._interval)

    def __enter__(self) -> _Heartbeat:
        self._thread.start()
        # Let the thread reach its loop so a zero tick count later means the
        # GIL was withheld, not that the thread never started.
        while self.ticks == 0:
            time.sleep(self._interval)
        self.ticks = 0
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


class GilReleaseTest(unittest.TestCase):
    def test_a_long_extraction_lets_other_python_threads_run(self) -> None:
        """Compare the heartbeat's rate during an extraction to its idle rate.

        A bare `ticks > 0` would pass for an extension that released the GIL
        once in half a second. Comparing against `elapsed / interval` instead
        does not work either: `time.sleep(0.001)` does not yield a thousand
        wake-ups a second on any real OS -- timer granularity and scheduling
        put the achievable rate well below that, and the shortfall varies by
        host. So the baseline is measured on the same host, in the same run,
        over a window of the same length with nothing else going on.
        """
        with tempfile.TemporaryDirectory(prefix="rookie-python-gil-") as temp:
            database, window = _sized_store(Path(temp))
            with _Heartbeat() as heartbeat:
                time.sleep(window)
                idle_ticks = heartbeat.ticks

                heartbeat.ticks = 0
                started = time.perf_counter()
                rookie_cookies.from_path(str(database))
                elapsed = time.perf_counter() - started
                busy_ticks = heartbeat.ticks

        # `_sized_store` guarantees the window; assert it again because a warm
        # page cache can make the second read of the same file faster.
        self.assertGreater(
            elapsed,
            _MIN_WINDOW_SECONDS / 2,
            f"extraction took {elapsed:.4f}s, too short to prove anything",
        )
        self.assertGreater(idle_ticks, 0, "the heartbeat never ran while idle")
        # The hard contract: a held GIL means exactly zero ticks on any
        # machine, because the heartbeat cannot run a single bytecode without
        # it.
        self.assertGreater(
            busy_ticks,
            0,
            f"no Python thread ran during a {elapsed:.3f}s extraction; the GIL "
            "was held",
        )
        # And a loose rate bound on top, so "released it once in half a second"
        # cannot pass. Deliberately loose: an extraction is CPU-bound and
        # competes with the heartbeat for cores, so the busy rate is far below
        # the idle one even when the GIL is fully free -- a macOS CI runner
        # measured 37 ticks against ~190 idle, a fifth. A twentieth is
        # therefore the bound; anything tighter is fitted to one host.
        self.assertGreaterEqual(
            busy_ticks,
            idle_ticks / 20,
            f"{busy_ticks} ticks during a {elapsed:.3f}s extraction against "
            f"{idle_ticks} over an idle {window:.3f}s; the GIL was held for "
            "nearly all of it",
        )


class CancellationTest(unittest.TestCase):
    def test_a_handle_cancelled_before_the_call_stops_it(self) -> None:
        handle = rookie_cookies.CancellationHandle()
        self.assertTrue(handle.cancel())
        self.assertTrue(handle.is_cancelled())
        # Cancelling twice reports that this call was not the one that won.
        self.assertFalse(handle.cancel())

        with tempfile.TemporaryDirectory(prefix="rookie-python-cancel-") as temp:
            database = _seed_gecko(
                Path(temp) / "cookies.sqlite",
                [(".example.test", _LIVE_MS, "session", "value")],
            )
            with self.assertRaises(rookie_cookies.RookieStoppedError) as raised:
                rookie_cookies.cookies_from_path(str(database), None, None, handle)

        self.assertEqual(raised.exception.kind, "stopped")
        self.assertEqual(raised.exception.stop_reason, "cancelled")

    def test_a_handle_cancelled_from_another_thread_stops_an_in_flight_read(self) -> None:
        """Cancel from a thread that is already running, mid-extraction.

        A `threading.Timer` would race the extraction with its own thread
        startup, which on a fast release build the extraction can win. Starting
        the canceller first and waking it through an `Event` leaves only the
        wake-up itself, and `_sized_store` makes the extraction long enough to
        absorb that.
        """
        handle = rookie_cookies.CancellationHandle()
        start_cancelling = threading.Event()
        finished = threading.Event()

        def cancel_when_released() -> None:
            start_cancelling.wait(timeout=30)
            while not finished.is_set():
                if handle.cancel():
                    return
                time.sleep(0.001)

        canceller = threading.Thread(target=cancel_when_released, daemon=True)
        canceller.start()
        try:
            with tempfile.TemporaryDirectory(prefix="rookie-python-cancel-") as temp:
                database, _ = _sized_store(Path(temp))
                start_cancelling.set()
                with self.assertRaises(rookie_cookies.RookieStoppedError) as raised:
                    rookie_cookies.cookies_from_path(str(database), None, None, handle)
        finally:
            finished.set()
            start_cancelling.set()
            canceller.join(timeout=5)

        self.assertEqual(raised.exception.stop_reason, "cancelled")

    def test_an_expired_deadline_reports_a_distinct_stop_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rookie-python-timeout-") as temp:
            database = _seed_large(Path(temp) / "cookies.sqlite")
            # A zero budget is already expired at the first checkpoint, so this
            # one needs no window at all.
            with self.assertRaises(rookie_cookies.RookieStoppedError) as raised:
                rookie_cookies.cookies_from_path(str(database), None, 0.0)

        self.assertEqual(raised.exception.stop_reason, "timed_out")


class SameInterpreterConcurrencyTest(unittest.TestCase):
    def test_parallel_extractions_overlap_rather_than_queueing(self) -> None:
        """Four extractions at once finish faster than four in a row.

        Independent results alone prove nothing about concurrency: a binding
        that held the GIL, or funnelled every extraction through one mutex,
        would return the same four correct answers having run them one after
        another. Wall clock is what separates the two, so this compares the
        parallel run against a measured serial baseline.
        """
        workers = 4
        if (os.cpu_count() or 1) < 2:
            self.skipTest("a single-core host cannot overlap CPU-bound work")

        with tempfile.TemporaryDirectory(prefix="rookie-python-overlap-") as temp:
            # One store, read by every worker. Distinct stores are what
            # `test_parallel_extractions_do_not_interfere` is for; here the
            # question is whether the binding serializes, and four readers on
            # one file answers it without seeding four large databases.
            store, serial = _sized_store(Path(temp))

            barrier = threading.Barrier(workers)
            failures: list[BaseException] = []

            def extract(index: int) -> None:
                try:
                    barrier.wait(timeout=30)
                    rookie_cookies.from_path(str(store))
                except BaseException as error:  # noqa: BLE001 - re-raised below
                    failures.append(error)

            threads = [
                threading.Thread(target=extract, args=(index,)) for index in range(workers)
            ]
            started = time.perf_counter()
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=120)
            parallel = time.perf_counter() - started

        # Asserted before any instrumentation check, so a coverage lane still
        # runs four concurrent extractions over one store and still fails on a
        # crash, an exception, or a thread that never finished. Only the
        # wall-clock inference below is stood down there.
        self.assertEqual(failures, [])
        self.assertFalse([thread for thread in threads if thread.is_alive()])
        if _COVERAGE_INSTRUMENTED:
            self.skipTest(_INSTRUMENTED_SKIP_REASON)
        # Two cores are enough to beat a fully serial run by a clear margin;
        # the bound is loose so a busy runner does not turn a real overlap into
        # a red build, while a fully serialized binding still fails it.
        self.assertLess(
            parallel,
            workers * serial * 0.85,
            f"{workers} extractions took {parallel:.3f}s against a {serial:.3f}s "
            "serial baseline, which is what fully serialized work looks like",
        )

    def test_parallel_extractions_do_not_interfere(self) -> None:
        workers = 4
        with tempfile.TemporaryDirectory(prefix="rookie-python-parallel-") as temp:
            databases = [
                _seed_gecko(
                    Path(temp) / f"cookies-{index}.sqlite",
                    [(".example.test", _LIVE_MS, f"session-{index}", f"value-{index}")],
                )
                for index in range(workers)
            ]
            results: list[Optional[list[dict]]] = [None] * workers
            failures: list[BaseException] = []

            def extract(index: int) -> None:
                try:
                    results[index] = rookie_cookies.cookies_from_path(
                        str(databases[index])
                    )
                except BaseException as error:  # noqa: BLE001 - re-raised below
                    failures.append(error)

            barrier = threading.Barrier(workers)

            def run(index: int) -> None:
                barrier.wait()
                extract(index)

            threads = [
                threading.Thread(target=run, args=(index,)) for index in range(workers)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)

        self.assertEqual(failures, [])
        for index, rows in enumerate(results):
            with self.subTest(worker=index):
                self.assertIsNotNone(rows)
                assert rows is not None
                self.assertEqual([row["name"] for row in rows], [f"session-{index}"])
                self.assertEqual([row["value"] for row in rows], [f"value-{index}"])


class LoggingBridgeTest(unittest.TestCase):
    def _capture(self) -> tuple[list[logging.LogRecord], tuple[object, int, object]]:
        """Record everything an extraction logs, from the root down.

        The handler goes on the ROOT logger, not on `rookie_cookies`. pyo3-log
        dispatches through `logging.getLogger(target).handle(...)`, so a handler
        attached to the package logger can only ever receive the package's own
        records -- asserting they are under `rookie_cookies` would be a
        tautology. Capturing at the root is what makes a dependency crate's log
        (zbus, rustls, the SQLite bindings) visible, which is the pollution the
        `LevelFilter::Off` in `bindings/python/src/lib.rs` exists to prevent.
        """
        root = logging.getLogger()
        root_state = (list(root.handlers), root.level, list(root.filters))
        previous_root_level = root.level

        package = logging.getLogger("rookie_cookies")
        previous_level = package.level
        captured: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured.append(record)

        handler = Capture()
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        package.setLevel(logging.DEBUG)
        try:
            with tempfile.TemporaryDirectory(prefix="rookie-python-log-") as temp:
                database = _seed_gecko(
                    Path(temp) / "cookies.sqlite",
                    [(".example.test", _LIVE_MS, "session", "value")],
                )
                rookie_cookies.cookies_from_path(str(database))
                rookie_cookies.cookies_from_path(str(database))
        finally:
            root.removeHandler(handler)
            root.setLevel(previous_root_level)
            package.setLevel(previous_level)
        return captured, root_state

    def test_the_bridge_leaves_the_root_logger_untouched(self) -> None:
        # Unconditional: this half holds whether or not any record is emitted,
        # so it is kept separate from the half that needs one. `_capture`
        # restores what it changed, so the comparison is against the state
        # before it ran.
        _, root_state = self._capture()
        root = logging.getLogger()
        self.assertEqual((list(root.handlers), root.level, list(root.filters)), root_state)

    def test_no_dependency_crate_logs_outside_the_package_logger(self) -> None:
        """Every record an extraction produces belongs to `rookie_cookies`.

        Captured at the root, so a dependency crate escaping the binding's
        `LevelFilter::Off` shows up here as a record named `zbus`, `rustls`,
        or similar rather than being invisible.
        """
        captured, _ = self._capture()
        if not captured:
            # pyo3-log caches each Rust target's level the first time that
            # target logs and never revisits it, so this can only observe
            # records when this module's import-time `setLevel` ran before any
            # extraction anywhere in the process. Skipping with the reason
            # beats failing on a true statement about the bridge.
            self.skipTest(
                "pyo3-log had already cached this target's level before this "
                "module was imported; run the whole tests/python suite, or this "
                "file on its own"
            )
        for record in captured:
            with self.subTest(logger=record.name):
                self.assertTrue(
                    record.name == "rookie_cookies"
                    or record.name.startswith("rookie_cookies."),
                    f"the bridge emitted outside the package logger: {record.name}",
                )

    def test_importing_the_package_installs_no_root_handler(self) -> None:
        """Checked in a fresh interpreter, because this one already imported it.

        `importlib.import_module` on an already-loaded module returns it from
        `sys.modules` without re-running initialization, so an in-process check
        could not see an import-time side effect at all.
        """
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                "import logging, rookie_cookies;"
                " root = logging.getLogger();"
                " print(len(root.handlers), root.level)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        handlers, level = result.stdout.split()
        self.assertEqual(handlers, "0", "importing the package installed a root handler")
        self.assertEqual(level, str(logging.WARNING), "import changed the root level")


class DiagnosticAttributeTest(unittest.TestCase):
    """Every raised exception carries the full attribute set, never a subset."""

    STABLE_ATTRIBUTES = (
        "kind",
        "code",
        "stop_reason",
        "profile_ids",
        "source_kind",
        "target_os",
        "path_redacted",
        "required",
    )

    def _raise(self, probe) -> BaseException:
        with self.assertRaises(rookie_cookies.RookieError) as raised:
            probe()
        return raised.exception

    def test_each_exception_class_exposes_every_stable_attribute(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rookie-python-errors-") as temp:
            missing = str(Path(temp) / "missing" / "Cookies")
            database = _seed_gecko(
                Path(temp) / "cookies.sqlite",
                [(".example.test", _LIVE_MS, "session", "value")],
            )
            handle = rookie_cookies.CancellationHandle()
            handle.cancel()
            probes = {
                rookie_cookies.RookieRequestError: lambda: rookie_cookies.read(
                    browser="not-a-registered-browser"
                ),
                rookie_cookies.RookieSourceError: lambda: rookie_cookies.from_path(
                    missing
                ),
                rookie_cookies.RookieStoppedError: lambda: rookie_cookies.cookies_from_path(
                    str(database), None, None, handle
                ),
                rookie_cookies.RookieEngineError: lambda: rookie_cookies.firefox_based(
                    missing
                ),
            }
            for expected, probe in probes.items():
                with self.subTest(exception=expected.__name__):
                    error = self._raise(probe)
                    self.assertIsInstance(error, expected)
                    for attribute in self.STABLE_ATTRIBUTES:
                        self.assertTrue(
                            hasattr(error, attribute),
                            f"{expected.__name__} is missing {attribute}",
                        )

    def test_required_is_populated_for_both_codes_that_define_it(self) -> None:
        """`required` is a shared vocabulary, not an incomplete-context field.

        Every error carries the attribute (the test above), but only two codes
        ever fill it: `incomplete_send_context` and, from 0.7,
        `isolation_loss_refused`. A caller that already branches on one's
        `required` must not need a second vocabulary for the other, so this
        pins that both are non-empty and that they agree.
        """
        with tempfile.TemporaryDirectory(prefix="rookie-python-required-") as temp:
            database = Path(temp) / "cookies.sqlite"
            connection = sqlite3.connect(str(database))
            try:
                connection.execute("PRAGMA user_version = 16")
                connection.execute(
                    """
                    CREATE TABLE moz_cookies (
                      host TEXT NOT NULL,
                      name TEXT NOT NULL,
                      value TEXT NOT NULL,
                      path TEXT NOT NULL,
                      isSecure INTEGER NOT NULL,
                      isHttpOnly INTEGER NOT NULL,
                      sameSite INTEGER NOT NULL,
                      expiry INTEGER NOT NULL,
                      originAttributes TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO moz_cookies VALUES"
                    " ('embedded.example.test', 'chips', 'value', '/', 1, 0, 0, ?, ?)",
                    (
                        _LIVE_MS,
                        "^partitionKey=%28https%2Ctop.example.test%29",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            snapshot = rookie_cookies.from_path(str(database), include_expired=True)

        with self.assertRaises(rookie_cookies.RookieRequestError) as refused:
            snapshot.as_jar()
        self.assertEqual(refused.exception.code, "isolation_loss_refused")
        self.assertEqual(list(refused.exception.required), ["top_level_site"])

        with self.assertRaises(rookie_cookies.RookieRequestError) as incomplete:
            snapshot.header("https://embedded.example.test/")
        self.assertEqual(incomplete.exception.code, "incomplete_send_context")
        self.assertEqual(
            list(incomplete.exception.required), list(refused.exception.required)
        )

        # An unrelated request error keeps the attribute and leaves it empty,
        # so `if error.required:` is a safe way to branch.
        with self.assertRaises(rookie_cookies.RookieRequestError) as unrelated:
            rookie_cookies.read(browser="not-a-registered-browser")
        self.assertEqual(list(unrelated.exception.required), [])

    def test_the_hierarchy_keeps_its_pre_existing_builtin_bases(self) -> None:
        self.assertTrue(issubclass(rookie_cookies.RookieError, Exception))
        for cls in (
            rookie_cookies.RookieRequestError,
            rookie_cookies.RookieSourceError,
        ):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, rookie_cookies.RookieError))
                self.assertTrue(issubclass(cls, ValueError))
        for cls in (
            rookie_cookies.RookieStoppedError,
            rookie_cookies.RookieEngineError,
        ):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, rookie_cookies.RookieError))
                self.assertTrue(issubclass(cls, RuntimeError))
        self.assertTrue(
            issubclass(
                rookie_cookies.RookieSourceError, rookie_cookies.RookieRequestError
            )
        )

    def test_resource_exhaustion_has_no_python_reachable_trigger(self) -> None:
        """`resource_exhausted` is mapped but not yet reachable from Python.

        `CancellationToken::exhaust_resources` is an internal seam no public
        entry point drives today, so the stop-reason mapping is covered by
        `bindings/python/src/errors.rs`'s own tests rather than from here. This
        test records that state: if a Python-reachable trigger ever appears,
        the stop reasons observable here stop matching and this fails.
        """
        with tempfile.TemporaryDirectory(prefix="rookie-python-exhaust-") as temp:
            database = _seed_large(Path(temp) / "cookies.sqlite")
            observed = set()
            # Both probes are already terminal at the first checkpoint, so
            # neither depends on how long the extraction would have taken.
            handle = rookie_cookies.CancellationHandle()
            handle.cancel()
            for probe in (
                lambda: rookie_cookies.cookies_from_path(str(database), None, 0.0),
                lambda: rookie_cookies.cookies_from_path(
                    str(database), None, None, handle
                ),
            ):
                with self.assertRaises(rookie_cookies.RookieStoppedError) as raised:
                    probe()
                observed.add(raised.exception.stop_reason)
        self.assertEqual(observed, {"timed_out", "cancelled"})


class ReadWarningTest(unittest.TestCase):
    def _warned(self, temp: str) -> rookie_cookies.ReadWarning:
        database = _seed_gecko(
            Path(temp) / "cookies.sqlite", [(".example.test", _LIVE_MS, "sid\r", "value")]
        )
        result = rookie_cookies.from_path(str(database), include_expired=True)
        return next(
            warning for warning in result.warnings if warning.code == "invalid_octets"
        )

    def test_str_summarizes_and_repr_round_trips_the_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rookie-python-warning-") as temp:
            warning = self._warned(temp)
        self.assertEqual(warning.count, 1)
        self.assertIn("invalid_octets", str(warning))
        self.assertEqual(repr(warning), 'ReadWarning(code="invalid_octets", count=1)')


class UnicodeTest(unittest.TestCase):
    def test_unicode_cookie_fields_round_trip_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rookie-python-unicode-") as temp:
            database = _seed_gecko(
                Path(temp) / "cookies.sqlite",
                [(_UNICODE_DOMAIN, _LIVE_MS, _UNICODE_NAME, _UNICODE_VALUE)],
            )
            rows = rookie_cookies.cookies_from_path(str(database))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], _UNICODE_DOMAIN)
        self.assertEqual(rows[0]["name"], _UNICODE_NAME)
        self.assertEqual(rows[0]["value"], _UNICODE_VALUE)

    def test_a_unicode_filesystem_path_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rookie-python-unicode-") as temp:
            directory = Path(temp) / _UNICODE_DIRECTORY
            directory.mkdir()
            database = _seed_gecko(
                directory / "cookies.sqlite",
                [(".example.test", _LIVE_MS, "session", "value")],
            )
            rows = rookie_cookies.cookies_from_path(str(database))

        self.assertEqual([row["name"] for row in rows], ["session"])

    def test_a_unicode_path_survives_the_netscape_projection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rookie-python-unicode-") as temp:
            database = _seed_gecko(
                Path(temp) / "cookies.sqlite",
                [(_UNICODE_DOMAIN, _LIVE_MS, _UNICODE_NAME, _UNICODE_VALUE)],
            )
            text = rookie_cookies.to_netscape(
                rookie_cookies.cookies_from_path(str(database))
            )

        self.assertIn(_UNICODE_VALUE, text)
        self.assertIn(_UNICODE_DOMAIN, text)


class RepeatedImportTest(unittest.TestCase):
    def test_the_extension_survives_being_imported_twice(self) -> None:
        """Import, drop from `sys.modules`, import again -- in a fresh process.

        Doing this in-process would prove nothing: `import` on a loaded module
        is a `sys.modules` lookup, so the second one never re-runs the
        extension's initialization. Dropping the entry first is what forces
        PyO3's module init to execute a second time, which is where a
        single-initialization assumption would surface.
        """
        program = (
            "import sys\n"
            "import rookie_cookies\n"
            "first = rookie_cookies.version()\n"
            "for name in [n for n in sys.modules if n.startswith('rookie_cookies')]:\n"
            "    del sys.modules[name]\n"
            "import rookie_cookies as reloaded\n"
            "assert reloaded.version() == first\n"
            "assert reloaded.chrome is not None\n"
            "print('ok')\n"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", program],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"re-importing the extension failed:\n{result.stderr}",
        )
        self.assertEqual(result.stdout.strip(), "ok")

    def test_the_loaded_module_is_the_one_the_package_re_exports(self) -> None:
        import importlib

        native = importlib.import_module("rookie_cookies.rookie_cookies")
        self.assertIs(native.ReadResult, rookie_cookies.ReadResult)
        self.assertIs(sys.modules["rookie_cookies"], rookie_cookies)


if __name__ == "__main__":
    unittest.main()
