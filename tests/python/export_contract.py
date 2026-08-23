"""The declarative contract every public `rookie_cookies` export is held to.

One `Export` row per name in `__all__`, including the platform-conditional
ones. `test_export_contract.py` turns each row into five assertions: the
runtime export exists exactly where the row says it does, the stub agrees, the
parameter shape and defaults match, one call succeeds, and one call fails with
the classified exception the row declares.

Adding a public export without adding its row here fails
`test_every_public_export_has_a_contract_row`, so the table cannot silently
fall behind the module.

Two deliberate omissions:

* Annotations are not part of `Export.signature`. `inspect.signature` renders
  them differently across the 3.11-3.14 interpreters this wheel supports, and
  annotation fidelity is `scripts/check-python-stubs.py`'s job. What is pinned
  here is the part a caller writes: names, ordering, keyword-only-ness, and
  defaults.
* Browsers whose registry root is a glob, or whose store is not a SQLite file
  this suite can synthesize, carry a `seeding_exception` instead of a success
  probe. Their success path is the exact-corpus E2E lane; see
  `tests/e2e/browser_coverage.json`.
"""

from __future__ import annotations

import contextlib
import inspect
import json
import os
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Optional
from unittest import mock

import rookie_cookies

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "rookie-rs/browser_registry.json"

LINUX = "linux"
MACOS = "darwin"
WINDOWS = "win32"
ALL_PLATFORMS = frozenset({LINUX, MACOS, WINDOWS})

# The registry names platforms differently from `sys.platform`; the binding's
# cfg gates follow the latter, so the contract does too.
REGISTRY_PLATFORMS = {LINUX: "linux", MACOS: "macos", WINDOWS: "windows"}

SEEDED_DOMAIN = ".example.test"
SEEDED_NAME = "contract"
SEEDED_VALUE = "seeded-value"


def current_platform() -> str:
    if sys.platform.startswith("linux"):
        return LINUX
    if sys.platform in ALL_PLATFORMS:
        return sys.platform
    raise RuntimeError(f"unsupported platform for the export contract: {sys.platform}")


# --------------------------------------------------------------------------
# Parameter shape
# --------------------------------------------------------------------------


def parameter_spec(obj: object) -> str:
    """Render a callable's parameter names, ordering, and defaults.

    Annotations are dropped on purpose -- see this module's docstring.
    """
    parameters = list(inspect.signature(obj).parameters.values())
    rendered: list[str] = []
    keyword_marker_emitted = False
    positional_only = 0
    for parameter in parameters:
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            positional_only += 1
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY and not keyword_marker_emitted:
            rendered.append("*")
            keyword_marker_emitted = True
        prefix = {
            inspect.Parameter.VAR_POSITIONAL: "*",
            inspect.Parameter.VAR_KEYWORD: "**",
        }.get(parameter.kind, "")
        text = f"{prefix}{parameter.name}"
        if parameter.default is not inspect.Parameter.empty:
            text += f"={parameter.default!r}"
        rendered.append(text)
    if positional_only:
        rendered.insert(positional_only, "/")
    return "(" + ", ".join(rendered) + ")"


# --------------------------------------------------------------------------
# Registry-backed seeding
# --------------------------------------------------------------------------


class UnseedableBrowser(RuntimeError):
    """The registry root for this browser cannot be materialized by the suite."""


def registry_entries(platform: str) -> dict[str, dict[str, Any]]:
    payload = json.loads(REGISTRY.read_text(encoding="utf-8"))
    entries = payload["platforms"][REGISTRY_PLATFORMS[platform]]
    return {entry["canonical_id"]: entry for entry in entries}


def _synthetic_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "APPDATA": str(home / "AppData" / "Roaming"),
    }


@contextlib.contextmanager
def synthetic_home() -> Iterator[Path]:
    """An empty home every root-discovery variable points at.

    Probes seed into this home through the same registry templates the binding
    reads, so a browser installed on the host can never decide whether an
    assertion passes.
    """
    with tempfile.TemporaryDirectory(prefix="rookie-export-contract-") as temp:
        home = Path(temp)
        with mock.patch.dict(os.environ, _synthetic_environment(home), clear=False):
            os.environ.pop("CHROME_CONFIG_HOME", None)
            yield home


def resolve_registry_root(template: str, home: Path) -> Path:
    """Expand a registry root template against a synthetic home.

    Mirrors `tests/e2e/run_exact_corpus_e2e.py:resolve_registry_root`. A
    template that still holds a placeholder or a glob after expansion is not
    something this suite can create on disk.
    """
    environment = _synthetic_environment(home)
    replacements = {
        "{home}": environment["HOME"],
        "{config_home}": environment["XDG_CONFIG_HOME"],
        "{xdg_config_home}": environment["XDG_CONFIG_HOME"],
        "{local_app_data}": environment["LOCALAPPDATA"],
        "{roaming_app_data}": environment["APPDATA"],
    }
    resolved = template
    for placeholder, value in replacements.items():
        resolved = resolved.replace(placeholder, value)
    if "{" in resolved or "}" in resolved or "*" in resolved:
        raise UnseedableBrowser(f"unresolvable registry root {template!r}")
    return Path(resolved)


def preferred_root(entry: dict[str, Any], home: Path) -> tuple[Path, str]:
    """The lowest-priority root the suite can materialize, and its discovery kind."""
    failures: list[str] = []
    for root in sorted(entry["roots"], key=lambda item: item["priority"]):
        try:
            return resolve_registry_root(root["template"], home), root["discovery"]
        except UnseedableBrowser as error:
            failures.append(str(error))
    raise UnseedableBrowser(
        f"no materializable root for {entry['canonical_id']!r}: {'; '.join(failures)}"
    )


def seed_chromium_user_data(root: Path) -> None:
    """Seed both Chromium profile layouts under one user-data root.

    Chrome-shaped browsers keep profiles in `<root>/Default`; Opera and Opera GX
    make the user-data root itself the profile. Writing both means one seeder
    covers every `chromium_user_data` root in the registry.
    """
    for database in (root / "Default" / "Network" / "Cookies", root / "Network" / "Cookies"):
        _write_chromium_database(database)
    (root / "Local State").write_text("{}", encoding="utf-8")


def _write_chromium_database(database: Path) -> None:
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database))
    try:
        connection.executescript(
            """
            CREATE TABLE meta (key TEXT NOT NULL UNIQUE PRIMARY KEY, value TEXT);
            INSERT INTO meta VALUES ('version', '23');
            CREATE TABLE cookies (
              host_key TEXT NOT NULL,
              path TEXT NOT NULL,
              is_secure INTEGER NOT NULL,
              expires_utc INTEGER NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              encrypted_value BLOB NOT NULL,
              is_httponly INTEGER NOT NULL,
              samesite INTEGER NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO cookies VALUES (?, '/', 0, 0, ?, ?, X'', 0, 0)",
            (SEEDED_DOMAIN, SEEDED_NAME, SEEDED_VALUE),
        )
        connection.commit()
    finally:
        connection.close()


def seed_mozilla_profiles_ini(root: Path) -> None:
    profile = root / "Profiles" / "contract-release"
    profile.mkdir(parents=True, exist_ok=True)
    (root / "profiles.ini").write_text(
        "[InstallContract]\n"
        "Default=Profiles/contract-release\n"
        "\n"
        "[Profile0]\n"
        "Name=contract-release\n"
        "IsRelative=1\n"
        "Path=Profiles/contract-release\n"
        "Default=1\n",
        encoding="utf-8",
    )
    connection = sqlite3.connect(str(profile / "cookies.sqlite"))
    try:
        connection.execute("PRAGMA user_version = 16")
        connection.execute(
            """
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
        )
        connection.execute(
            "INSERT INTO moz_cookies VALUES (?, '/', 0, 4102444800000, ?, ?, 0, 0)",
            (SEEDED_DOMAIN, SEEDED_NAME, SEEDED_VALUE),
        )
        connection.commit()
    finally:
        connection.close()


SEEDERS: dict[str, Callable[[Path], None]] = {
    "chromium_user_data": seed_chromium_user_data,
    "mozilla_profiles_ini": seed_mozilla_profiles_ini,
}


def seed_browser(home: Path, browser_id: str) -> None:
    """Install one seeded profile where the registry says this browser lives."""
    entry = registry_entries(current_platform()).get(browser_id)
    if entry is None:
        raise UnseedableBrowser(f"{browser_id!r} is not registered on this platform")
    root, discovery = preferred_root(entry, home)
    seeder = SEEDERS.get(discovery)
    if seeder is None:
        raise UnseedableBrowser(f"no seeder for discovery kind {discovery!r}")
    root.mkdir(parents=True, exist_ok=True)
    seeder(root)


# --------------------------------------------------------------------------
# Expectations
# --------------------------------------------------------------------------


def _is_cookie_list(value: object) -> Optional[str]:
    if not isinstance(value, list):
        return f"expected a list, got {type(value).__name__}"
    for row in value:
        if not isinstance(row, dict) or "name" not in row:
            return f"expected cookie mappings, got {row!r}"
    return None


def expect_seeded_cookie(value: object) -> Optional[str]:
    problem = _is_cookie_list(value)
    if problem is not None:
        return problem
    assert isinstance(value, list)
    matches = [row for row in value if row["name"] == SEEDED_NAME]
    if not matches:
        return f"seeded cookie {SEEDED_NAME!r} missing from {value!r}"
    if matches[0]["value"] != SEEDED_VALUE:
        return f"seeded cookie value was {matches[0]['value']!r}"
    return None


def expect_cookie_list(value: object) -> Optional[str]:
    return _is_cookie_list(value)


def expect_detailed_cookies(value: object) -> Optional[str]:
    if not isinstance(value, list):
        return f"expected a list, got {type(value).__name__}"
    for row in value:
        if not isinstance(row, dict) or set(row) != {"cookie", "context"}:
            return f"expected detailed cookie records, got {row!r}"
    return None


def expect_report(value: object) -> Optional[str]:
    if not isinstance(value, dict) or "status" not in value:
        return f"expected an extraction report mapping, got {value!r}"
    return None


def expect_dto_report(value: object) -> Optional[str]:
    if not isinstance(value, rookie_cookies.dto.ExtractionReport):
        return f"expected dto.ExtractionReport, got {type(value).__name__}"
    return None


def expect_descriptor_list(value: object) -> Optional[str]:
    if not isinstance(value, list):
        return f"expected a list, got {type(value).__name__}"
    return None


def expect_dto_list(kind: type) -> Callable[[object], Optional[str]]:
    def check(value: object) -> Optional[str]:
        if not isinstance(value, list):
            return f"expected a list, got {type(value).__name__}"
        for item in value:
            if not isinstance(item, kind):
                return f"expected {kind.__name__} items, got {type(item).__name__}"
        return None

    return check


def expect_nonempty_string(value: object) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return f"expected a non-empty string, got {value!r}"
    return None


def expect_cookiejar(value: object) -> Optional[str]:
    import http.cookiejar

    if not isinstance(value, http.cookiejar.CookieJar):
        return f"expected a CookieJar, got {type(value).__name__}"
    return None


def expect_read_result(value: object) -> Optional[str]:
    if not isinstance(value, rookie_cookies.ReadResult):
        return f"expected ReadResult, got {type(value).__name__}"
    return expect_seeded_cookie(value.as_list())


# --------------------------------------------------------------------------
# The contract table
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Failure:
    """A call that must raise one specific classified exception.

    `kind` and `code` are the binding's stable diagnostic attributes. They are
    `None` for the plain interpreter errors raised before any request is built,
    which carry no rookie classification.
    """

    probe: Callable[[Path], object]
    exception: type[BaseException]
    kind: Optional[str] = None
    code: Optional[str] = None


@dataclass(frozen=True)
class Export:
    name: str
    kind: str
    platforms: frozenset[str] = ALL_PLATFORMS
    signature: Optional[str] = None
    # Every native callable is declared in rookie_cookies.pyi; the pure-Python
    # cookiejar/netscape helpers predate the stub and are documented in
    # bindings/python/README.md instead.
    in_stub: bool = True
    success: Optional[Callable[[Path], object]] = None
    expect: Optional[Callable[[object], Optional[str]]] = None
    failure: Optional[Failure] = None
    seeding_exception: Optional[str] = None
    notes: str = ""


MISSING = "rookie-export-contract-missing"


def _missing_path(home: Path) -> str:
    return str(home / MISSING / "Cookies")


def _browser_success(browser_id: str) -> Callable[[Path], object]:
    def probe(home: Path) -> object:
        seed_browser(home, browser_id)
        return getattr(rookie_cookies, browser_id)([SEEDED_DOMAIN.lstrip(".")])

    return probe


def _browser_failure(browser_id: str) -> Failure:
    # With a synthetic home and nothing seeded, discovery finds no store. That
    # is the classified engine error, not an empty list -- the binding
    # distinguishes "no browser here" from "browser here, no cookies".
    return Failure(
        probe=lambda home: getattr(rookie_cookies, browser_id)(),
        exception=rookie_cookies.RookieEngineError,
        kind="engine",
        code="no_discovered_source",
    )


def _browser_export(
    name: str,
    platforms: frozenset[str] = ALL_PLATFORMS,
    *,
    seeding_exception: Optional[str] = None,
) -> Export:
    return Export(
        name=name,
        kind="function",
        platforms=platforms,
        signature="(domains=None)",
        success=None if seeding_exception else _browser_success(name),
        expect=None if seeding_exception else expect_seeded_cookie,
        failure=_browser_failure(name),
        seeding_exception=seeding_exception,
    )


_SAFARI_EXCEPTION = (
    "Safari stores cookies in a binarycookies container this suite cannot "
    "synthesize; its success path is the macOS native E2E lane."
)
_IE_EXCEPTION = (
    "Internet Explorer reads an ESE WebCache database that only a real Windows "
    "install produces; its success path is the Windows fixture lane."
)
_OCTO_EXCEPTION = (
    "Octo Browser's registry root is a glob under a per-session temporary "
    "directory, so no fixed path exists for this suite to seed."
)

BROWSER_EXPORTS: tuple[Export, ...] = (
    _browser_export("arc", frozenset({MACOS, WINDOWS})),
    _browser_export("brave"),
    _browser_export("chrome"),
    _browser_export("chromium"),
    _browser_export("edge"),
    _browser_export("firefox"),
    _browser_export("librewolf"),
    _browser_export("opera"),
    _browser_export("vivaldi"),
    _browser_export("zen"),
    _browser_export("cachy", frozenset({LINUX})),
    _browser_export("opera_gx", frozenset({MACOS, WINDOWS})),
    _browser_export("safari", frozenset({MACOS}), seeding_exception=_SAFARI_EXCEPTION),
    _browser_export(
        "internet_explorer", frozenset({WINDOWS}), seeding_exception=_IE_EXCEPTION
    ),
    _browser_export(
        "octo_browser", frozenset({WINDOWS}), seeding_exception=_OCTO_EXCEPTION
    ),
)


def _load_success(home: Path) -> object:
    seed_browser(home, "chrome")
    return rookie_cookies.load([SEEDED_DOMAIN.lstrip(".")])


def _read_success(home: Path) -> object:
    seed_browser(home, "chrome")
    return rookie_cookies.read(browser="chrome", include_expired=True)


def _jar_success(home: Path) -> object:
    seed_browser(home, "chrome")
    return rookie_cookies.jar(browser="chrome", include_expired=True)


def _seeded_chromium_database(home: Path) -> str:
    seed_browser(home, "chrome")
    entry = registry_entries(current_platform())["chrome"]
    root, _ = preferred_root(entry, home)
    return str(root / "Default" / "Network" / "Cookies")


def _seeded_gecko_database(home: Path) -> str:
    seed_browser(home, "firefox")
    entry = registry_entries(current_platform())["firefox"]
    root, _ = preferred_root(entry, home)
    return str(root / "Profiles" / "contract-release" / "cookies.sqlite")


UNKNOWN_BROWSER = "not-a-registered-browser"


JOB_EXPORTS: tuple[Export, ...] = (
    Export(
        name="read",
        kind="function",
        signature=(
            "(*, browser, profile=None, include_expired=False, include_session=False, "
            "select=Ellipsis, timeout=None, cancellation=None, app_bound=Ellipsis)"
        ),
        success=_read_success,
        expect=expect_read_result,
        failure=Failure(
            probe=lambda home: rookie_cookies.read(browser=UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="jar",
        kind="function",
        signature=(
            "(*, browser, profile=None, include_expired=False, include_session=False, "
            "select='legacy_first', timeout=None, cancellation=None, "
            "app_bound='injection_only')"
        ),
        success=_jar_success,
        expect=expect_cookiejar,
        failure=Failure(
            probe=lambda home: rookie_cookies.jar(browser=UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="from_path",
        kind="function",
        signature=(
            "(path, *, include_expired=False, plaintext_only=False, browser_id=None, "
            "local_state_path=None, timeout=None, cancellation=None, app_bound=Ellipsis)"
        ),
        success=lambda home: rookie_cookies.from_path(_seeded_gecko_database(home)),
        expect=expect_read_result,
        failure=Failure(
            probe=lambda home: rookie_cookies.from_path(_missing_path(home)),
            exception=rookie_cookies.RookieSourceError,
            kind="source",
            code="not_a_regular_file",
        ),
    ),
    Export(
        name="extract_from_path",
        kind="function",
        signature=(
            "(path, *, domains=None, plaintext_only=False, browser_id=None, "
            "local_state_path=None, timeout=None, cancellation=None, app_bound=Ellipsis)"
        ),
        success=lambda home: rookie_cookies.extract_from_path(
            _seeded_gecko_database(home)
        ),
        expect=expect_seeded_cookie,
        failure=Failure(
            probe=lambda home: rookie_cookies.extract_from_path(_missing_path(home)),
            exception=rookie_cookies.RookieSourceError,
            kind="source",
            code="not_a_regular_file",
        ),
    ),
    Export(
        name="cookies_from_path",
        kind="function",
        signature="(path, domains=None, timeout=None, cancellation=None)",
        success=lambda home: rookie_cookies.cookies_from_path(
            _seeded_gecko_database(home)
        ),
        expect=expect_seeded_cookie,
        failure=Failure(
            probe=lambda home: rookie_cookies.cookies_from_path(_missing_path(home)),
            exception=rookie_cookies.RookieSourceError,
            kind="source",
            code="not_a_regular_file",
        ),
    ),
    Export(
        name="chromium_cookies_from_path",
        kind="function",
        signature="(path, options=None)",
        success=lambda home: rookie_cookies.chromium_cookies_from_path(
            _seeded_chromium_database(home)
        ),
        expect=expect_seeded_cookie,
        failure=Failure(
            probe=lambda home: rookie_cookies.chromium_cookies_from_path(
                _missing_path(home)
            ),
            exception=rookie_cookies.RookieSourceError,
            kind="source",
            code="not_a_regular_file",
        ),
    ),
    Export(
        name="chromium_cookies_from_path_detailed",
        kind="function",
        signature="(path, options=None)",
        success=lambda home: rookie_cookies.chromium_cookies_from_path_detailed(
            _seeded_chromium_database(home)
        ),
        expect=expect_detailed_cookies,
        failure=Failure(
            probe=lambda home: rookie_cookies.chromium_cookies_from_path_detailed(
                _missing_path(home)
            ),
            exception=rookie_cookies.RookieSourceError,
            kind="source",
            code="not_a_regular_file",
        ),
    ),
    Export(
        name="firefox_based",
        kind="function",
        signature="(db_path, domains=None)",
        success=lambda home: rookie_cookies.firefox_based(_seeded_gecko_database(home)),
        expect=expect_seeded_cookie,
        failure=Failure(
            probe=lambda home: rookie_cookies.firefox_based(_missing_path(home)),
            exception=rookie_cookies.RookieEngineError,
            kind="engine",
            code="source_extraction_failed",
        ),
    ),
    Export(
        name="firefox_based_detailed",
        kind="function",
        signature="(db_path, domains=None)",
        success=lambda home: rookie_cookies.firefox_based_detailed(
            _seeded_gecko_database(home)
        ),
        expect=expect_detailed_cookies,
        failure=Failure(
            probe=lambda home: rookie_cookies.firefox_based_detailed(
                _missing_path(home)
            ),
            exception=rookie_cookies.RookieEngineError,
            kind="engine",
            code="source_extraction_failed",
        ),
    ),
    Export(
        name="any_browser",
        kind="function",
        signature="(db_path, domains=None, key_path=None)",
        success=lambda home: rookie_cookies.any_browser(_seeded_gecko_database(home)),
        expect=expect_seeded_cookie,
        failure=Failure(
            probe=lambda home: rookie_cookies.any_browser(_missing_path(home)),
            exception=rookie_cookies.RookieEngineError,
            kind="engine",
            code="engine_failure",
        ),
    ),
    Export(
        name="load",
        kind="function",
        signature="(domains=None)",
        success=_load_success,
        expect=expect_seeded_cookie,
        # `load` sweeps every registered browser, so "nothing installed" is an
        # empty result rather than a fault. Its classified-error path is the
        # non-string domain list, which the binding rejects before any I/O.
        failure=Failure(
            probe=lambda home: rookie_cookies.load(1),  # type: ignore[arg-type]
            exception=TypeError,
        ),
    ),
)


CHROMIUM_BASED_SIGNATURE = (
    "(key_path, db_path, domains=None)"
    if sys.platform == WINDOWS
    else "(db_path, domains=None, browser_id=None)"
)


def _chromium_based_success(home: Path) -> object:
    database = _seeded_chromium_database(home)
    if sys.platform == WINDOWS:
        entry = registry_entries(current_platform())["chrome"]
        root, _ = preferred_root(entry, home)
        return rookie_cookies.chromium_based(str(root / "Local State"), database)
    return rookie_cookies.chromium_based(database)


def _chromium_based_detailed_success(home: Path) -> object:
    database = _seeded_chromium_database(home)
    if sys.platform == WINDOWS:
        entry = registry_entries(current_platform())["chrome"]
        root, _ = preferred_root(entry, home)
        return rookie_cookies.chromium_based_detailed(str(root / "Local State"), database)
    return rookie_cookies.chromium_based_detailed(database)


def _chromium_based_failure(detailed: bool) -> Failure:
    function = (
        rookie_cookies.chromium_based_detailed
        if detailed
        else rookie_cookies.chromium_based
    )

    def probe(home: Path) -> object:
        missing = _missing_path(home)
        if sys.platform == WINDOWS:
            return function(str(home / MISSING / "Local State"), missing)
        return function(missing)

    return Failure(
        probe=probe,
        exception=rookie_cookies.RookieEngineError,
        kind="engine",
        code="engine_failure",
    )


LEGACY_EXPORTS: tuple[Export, ...] = (
    Export(
        name="chromium_based",
        kind="function",
        signature=CHROMIUM_BASED_SIGNATURE,
        success=_chromium_based_success,
        expect=expect_seeded_cookie,
        failure=_chromium_based_failure(detailed=False),
        notes="deprecated since 0.6; kept until at least 0.7",
    ),
    Export(
        name="chromium_based_detailed",
        kind="function",
        signature=CHROMIUM_BASED_SIGNATURE,
        success=_chromium_based_detailed_success,
        expect=expect_detailed_cookies,
        failure=_chromium_based_failure(detailed=True),
        notes="deprecated since 0.6; kept until at least 0.7",
    ),
    Export(
        name="firefox_profiles",
        kind="function",
        signature="()",
        success=lambda home: (seed_browser(home, "firefox"), rookie_cookies.firefox_profiles())[1],
        expect=expect_descriptor_list,
        failure=Failure(
            probe=lambda home: rookie_cookies.firefox_profiles(),
            exception=rookie_cookies.RookieEngineError,
            kind="engine",
            code=None,
        ),
    ),
    Export(
        name="firefox_profile",
        kind="function",
        signature="(profile, domains=None)",
        success=lambda home: (
            seed_browser(home, "firefox"),
            rookie_cookies.firefox_profile("contract-release"),
        )[1],
        expect=expect_seeded_cookie,
        failure=Failure(
            probe=lambda home: rookie_cookies.firefox_profile("no-such-profile"),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_profile",
        ),
    ),
    Export(
        name="chrome_profiles",
        kind="function",
        signature="(*, timeout=None, cancellation=None)",
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.chrome_profiles())[1],
        expect=expect_descriptor_list,
        # An absent Chrome is an empty profile list, not a fault, so the
        # classified path is the cancelled handle instead.
        failure=Failure(
            probe=lambda home: rookie_cookies.chrome_profiles(
                cancellation=_cancelled_handle()
            ),
            exception=rookie_cookies.RookieStoppedError,
            kind="stopped",
            code="cancelled",
        ),
    ),
    Export(
        name="chrome_profile",
        kind="function",
        signature="(profile, domains=None)",
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.chrome_profile("Default"))[1],
        expect=expect_report,
        failure=Failure(
            probe=lambda home: rookie_cookies.chrome_profile("no-such-profile"),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_profile",
        ),
    ),
)


def _cancelled_handle() -> rookie_cookies.CancellationHandle:
    handle = rookie_cookies.CancellationHandle()
    handle.cancel()
    return handle


REPORT_EXPORTS: tuple[Export, ...] = (
    Export(
        name="supported_browsers",
        kind="function",
        signature="()",
        success=lambda home: rookie_cookies.supported_browsers(),
        expect=expect_descriptor_list,
        failure=None,
        notes="registry-only; it performs no I/O and has no failure path to classify",
    ),
    Export(
        name="supported_browsers_dto",
        kind="function",
        signature="()",
        in_stub=True,
        success=lambda home: rookie_cookies.supported_browsers_dto(),
        expect=expect_dto_list(rookie_cookies.dto.BrowserDescriptor),
        failure=None,
        notes="registry-only; it performs no I/O and has no failure path to classify",
    ),
    Export(
        name="browser_profiles",
        kind="function",
        signature="(browser_id, *, timeout=None, cancellation=None)",
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.browser_profiles("chrome"))[1],
        expect=expect_descriptor_list,
        failure=Failure(
            probe=lambda home: rookie_cookies.browser_profiles(UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="profiles",
        kind="function",
        signature="(browser_id, *, timeout=None, cancellation=None)",
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.profiles("chrome"))[1],
        expect=expect_descriptor_list,
        failure=Failure(
            probe=lambda home: rookie_cookies.profiles(UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="profiles_dto",
        kind="function",
        signature="(browser_id, *, timeout=None, cancellation=None)",
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.profiles_dto("chrome"))[1],
        expect=expect_dto_list(rookie_cookies.dto.ProfileDescriptor),
        failure=Failure(
            probe=lambda home: rookie_cookies.profiles_dto(UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="browser_report",
        kind="function",
        signature=(
            "(browser_id, profile_id=None, domains=None, *, select=None, timeout=None, "
            "cancellation=None, app_bound=Ellipsis)"
        ),
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.browser_report("chrome"))[1],
        expect=expect_report,
        failure=Failure(
            probe=lambda home: rookie_cookies.browser_report(UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="report",
        kind="function",
        signature=(
            "(browser, *, profile=None, domains=None, select=None, timeout=None, "
            "cancellation=None, app_bound='injection_only')"
        ),
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.report("chrome"))[1],
        expect=expect_report,
        failure=Failure(
            probe=lambda home: rookie_cookies.report(UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="report_dto",
        kind="function",
        signature=(
            "(browser, *, profile=None, domains=None, select=None, timeout=None, "
            "cancellation=None, app_bound='injection_only')"
        ),
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.report_dto("chrome"))[1],
        expect=expect_dto_report,
        failure=Failure(
            probe=lambda home: rookie_cookies.report_dto(UNKNOWN_BROWSER),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
            code="unknown_browser",
        ),
    ),
    Export(
        name="load_report",
        kind="function",
        signature="(domains=None, *, timeout=None, cancellation=None, app_bound=Ellipsis)",
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.load_report())[1],
        expect=expect_report,
        failure=Failure(
            probe=lambda home: rookie_cookies.load_report(app_bound="not-a-policy"),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
        ),
    ),
    Export(
        name="load_report_dto",
        kind="function",
        signature=(
            "(domains=None, *, timeout=None, cancellation=None, "
            "app_bound='injection_only')"
        ),
        success=lambda home: (seed_browser(home, "chrome"), rookie_cookies.load_report_dto())[1],
        expect=expect_dto_report,
        failure=Failure(
            probe=lambda home: rookie_cookies.load_report_dto(app_bound="not-a-policy"),
            exception=rookie_cookies.RookieRequestError,
            kind="request",
        ),
    ),
)


_SAMPLE_COOKIE = {
    "domain": SEEDED_DOMAIN,
    "path": "/",
    "secure": True,
    "expires": 1_700_000_000,
    "name": SEEDED_NAME,
    "value": SEEDED_VALUE,
    "http_only": True,
}

_STUBLESS = (
    "pure-Python cookiejar/netscape helper; predates rookie_cookies.pyi, which "
    "stubs the compiled submodule"
)

HELPER_EXPORTS: tuple[Export, ...] = (
    Export(
        name="version",
        kind="function",
        signature="()",
        success=lambda home: rookie_cookies.version(),
        expect=expect_nonempty_string,
        failure=None,
        notes="constant string; no failure path",
    ),
    Export(
        name="create_cookie",
        kind="function",
        signature="(host, path, secure, expires, name, value, http_only)",
        in_stub=False,
        success=lambda home: rookie_cookies.create_cookie(
            SEEDED_DOMAIN, "/", True, None, SEEDED_NAME, SEEDED_VALUE, True
        ).name,
        expect=expect_nonempty_string,
        failure=Failure(
            probe=lambda home: rookie_cookies.create_cookie(SEEDED_DOMAIN),  # type: ignore[call-arg]
            exception=TypeError,
        ),
        notes=_STUBLESS,
    ),
    Export(
        name="to_cookiejar",
        kind="function",
        signature="(cookies)",
        in_stub=False,
        success=lambda home: rookie_cookies.to_cookiejar([dict(_SAMPLE_COOKIE)]),
        expect=expect_cookiejar,
        failure=Failure(
            probe=lambda home: rookie_cookies.to_cookiejar([{"domain": SEEDED_DOMAIN}]),
            exception=KeyError,
        ),
        notes=_STUBLESS,
    ),
    Export(
        name="to_netscape",
        kind="function",
        signature="(cookies)",
        in_stub=False,
        success=lambda home: rookie_cookies.to_netscape([dict(_SAMPLE_COOKIE)]),
        expect=expect_nonempty_string,
        failure=Failure(
            probe=lambda home: rookie_cookies.to_netscape([{"domain": SEEDED_DOMAIN}]),
            exception=KeyError,
        ),
        notes=_STUBLESS,
    ),
)


VALUE_EXPORTS: tuple[Export, ...] = (
    Export(name="MAX_ISSUE_SAMPLES", kind="constant"),
    Export(name="dto", kind="module", in_stub=False, notes="submodule re-export"),
    Export(name="CancellationHandle", kind="class"),
    Export(name="ReadResult", kind="class"),
    Export(name="ReadWarning", kind="class"),
    Export(name="RookieError", kind="class"),
    Export(name="RookieRequestError", kind="class"),
    Export(name="RookieSourceError", kind="class"),
    Export(name="RookieStoppedError", kind="class"),
    Export(name="RookieEngineError", kind="class"),
    Export(name="AppBoundPolicy", kind="alias", in_stub=True),
    Export(name="SingleProfileSelection", kind="alias", in_stub=True),
    Export(name="ReportProfileSelection", kind="alias", in_stub=True),
    Export(name="ChromiumPathOptions", kind="alias", in_stub=True),
)


EXPORTS: tuple[Export, ...] = (
    BROWSER_EXPORTS + JOB_EXPORTS + LEGACY_EXPORTS + REPORT_EXPORTS
    + HELPER_EXPORTS + VALUE_EXPORTS
)

EXPORTS_BY_NAME: dict[str, Export] = {export.name: export for export in EXPORTS}


def applicable(export: Export) -> bool:
    return current_platform() in export.platforms
