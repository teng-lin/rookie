"""Interpreter-level contracts that only the binding can break.

Nothing here re-tests a decoder. These cover what sits between CPython and the
core: whether a long extraction holds the GIL, whether a handle cancelled from
another thread is observed mid-flight, whether two extractions can run in one
interpreter at once, whether the logging bridge stays inside the package's
logger, and whether Unicode survives both the value path and the path path.
"""

from __future__ import annotations

import logging
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
_EXPIRED_MS = 1_000_000_000
_LIVE_MS = 4_102_444_800_000

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

    def __init__(self, interval: float = 0.001) -> None:
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
        with tempfile.TemporaryDirectory(prefix="rookie-python-gil-") as temp:
            database, _ = _sized_store(Path(temp))
            with _Heartbeat() as heartbeat:
                started = time.perf_counter()
                rookie_cookies.from_path(str(database))
                elapsed = time.perf_counter() - started
                ticks = heartbeat.ticks

        # `_sized_store` guarantees the window; assert it again because a
        # warm page cache can make the second read of the same file faster.
        self.assertGreater(
            elapsed,
            _MIN_WINDOW_SECONDS / 2,
            f"extraction took {elapsed:.4f}s, too short to prove anything",
        )
        # Held GIL means exactly zero ticks, whatever the machine: the
        # heartbeat cannot run a single bytecode without it.
        self.assertGreater(
            ticks,
            0,
            f"no Python thread ran during a {elapsed:.3f}s extraction; the GIL was held",
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
        root = logging.getLogger()
        root_state = (list(root.handlers), root.level, list(root.filters))

        package = logging.getLogger("rookie_cookies")
        previous_level = package.level
        captured: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured.append(record)

        handler = Capture()
        package.addHandler(handler)
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
            package.removeHandler(handler)
            package.setLevel(previous_level)
        return captured, root_state

    def test_the_bridge_leaves_the_root_logger_untouched(self) -> None:
        # Unconditional: this half holds whether or not any record is emitted,
        # so it is kept separate from the half that needs one.
        _, root_state = self._capture()
        root = logging.getLogger()
        self.assertEqual((list(root.handlers), root.level, list(root.filters)), root_state)

    def test_records_stay_under_the_package_logger(self) -> None:
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
    def test_reimporting_the_extension_returns_the_same_objects(self) -> None:
        import importlib

        first = importlib.import_module("rookie_cookies.rookie_cookies")
        second = importlib.import_module("rookie_cookies.rookie_cookies")
        self.assertIs(first, second)
        self.assertIs(first.ReadResult, rookie_cookies.ReadResult)
        self.assertIs(sys.modules["rookie_cookies"], rookie_cookies)


if __name__ == "__main__":
    unittest.main()
