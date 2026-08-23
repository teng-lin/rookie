"""A type-checked consumer of the published `rookie_cookies` API.

This module is never executed. `scripts/check-python-stubs.py` runs mypy over
it against an *installed wheel*, so every annotation here is resolved through
the shipped `rookie_cookies.pyi` / `py.typed` -- the same path a downstream
user's type checker takes. Nothing at module scope may touch a real browser
profile: every call lives inside a function body that the checker analyzes and
the interpreter never runs.

`assert_type` is what makes this a contract rather than a spelling test. A name
that merely resolves proves only that the stub declares *something*; the
`assert_type` calls below fail the build if the declared type changes shape,
which is the drift that silently breaks consumers.
"""

from __future__ import annotations

import http.cookiejar
import sys
from typing import TYPE_CHECKING, Any, Dict, List, assert_type

import rookie_cookies
from rookie_cookies import dto

if TYPE_CHECKING:
    # Typing-only names: `DetailedCookie` is a TypedDict declared in the stub
    # for documentation and precision, and a compiled PyO3 module has no such
    # object at runtime. Importing it under TYPE_CHECKING is how a real
    # consumer names it without an ImportError.
    from rookie_cookies.rookie_cookies import CookieContext, CookieObject, DetailedCookie


def snapshot_reading() -> None:
    """`read` returns a ReadResult; its three projections keep their types."""
    result = rookie_cookies.read(browser="firefox")
    assert_type(result, rookie_cookies.ReadResult)

    # The eight-key projection and the isolation-intact one are distinct
    # views of the same snapshot, not interchangeable aliases.
    assert_type(result.as_list(), List[Dict[str, Any]])
    detailed = result.detailed_cookies()
    assert_type(detailed, List["DetailedCookie"])
    for record in detailed:
        assert_type(record["cookie"], "CookieObject")
        assert_type(record["context"], "CookieContext")
        assert_type(record["cookie"]["same_site"], int)
        assert_type(record["context"]["partition_key"], "str | None")

    # as_jar() is grafted onto ReadResult by __init__.py, but the stub has to
    # promise http.cookiejar.CookieJar or `jar.add_cookie_header(...)` below
    # is unresolvable for every downstream consumer.
    jar = result.as_jar()
    assert_type(jar, http.cookiejar.CookieJar)

    assert_type(result.browser_id, "str | None")
    assert_type(result.profile_id, "str | None")
    for warning in result.warnings:
        assert_type(warning.code, str)
        assert_type(warning.count, int)

    assert_type(len(result), int)
    assert_type(bool(result), bool)


def full_read_options() -> None:
    """Every documented keyword of `read` is accepted with its stated type."""
    handle = rookie_cookies.CancellationHandle()
    rookie_cookies.read(
        browser="chrome",
        profile="Default",
        include_expired=True,
        include_session=True,
        select="legacy_first",
        timeout=5.0,
        cancellation=handle,
        app_bound="disabled",
    )


def request_header_views() -> None:
    """`header` accepts a bare URL, a mapping, or keywords -- always -> str."""
    result = rookie_cookies.from_path("/nonexistent/Cookies")

    assert_type(result.header("https://example.com"), str)
    assert_type(
        result.header({"url": "https://example.com", "resource": "subresource"}),
        str,
    )
    # An explicit keyword composes with the mapping rather than conflicting.
    assert_type(
        result.header(
            {"url": "https://example.com"},
            top_level_site="https://example.com",
        ),
        str,
    )
    assert_type(
        result.header(
            url="https://example.com",
            top_level_site="https://example.com",
            resource="navigation",
            method="unsafe",
            user_context_id=1,
            private_browsing_id=0,
            now=1_700_000_000.0,
        ),
        str,
    )


def dto_helpers() -> None:
    """The DTO helpers return dataclasses, not the underlying dicts."""
    browsers = rookie_cookies.supported_browsers_dto()
    assert_type(browsers, List[dto.BrowserDescriptor])
    for browser in browsers:
        assert_type(browser.id, str)
        assert_type(browser.aliases, List[str])
        assert_type(browser.capabilities.available_decryption_tiers, List[str])

        profiles = rookie_cookies.profiles_dto(browser.id)
        assert_type(profiles, List[dto.ProfileDescriptor])
        for profile in profiles:
            assert_type(profile.is_default, bool)
            assert_type(profile.profile.display_name, str)

    report = rookie_cookies.report_dto("firefox", domains=["example.com"])
    assert_type(report, dto.ExtractionReport)
    assert_type(report.summary.browsers_detected, int)
    assert_type(report.schema_version, int)

    loaded = rookie_cookies.load_report_dto(["example.com"])
    assert_type(loaded, dto.ExtractionReport)
    assert_type(loaded.termination, str)

    # The untyped view is still a plain dict, so both remain available.
    assert_type(rookie_cookies.report("firefox"), Dict[str, Any])


def cancellation() -> None:
    """A handle is constructible, shareable, and returns bools."""
    handle = rookie_cookies.CancellationHandle()
    assert_type(handle.cancel(), bool)
    assert_type(handle.is_cancelled(), bool)

    # The same handle is accepted by every long-running entry point.
    rookie_cookies.browser_profiles("chrome", cancellation=handle)
    rookie_cookies.load_report(None, cancellation=handle)
    rookie_cookies.jar(browser="chrome", cancellation=handle)


def error_taxonomy() -> None:
    """The exception hierarchy and its stable diagnostic attributes."""
    try:
        rookie_cookies.read(browser="firefox")
    except rookie_cookies.RookieStoppedError as error:
        assert_type(error.stop_reason, "str | None")
    except rookie_cookies.RookieSourceError as error:
        assert_type(error.source_kind, "str | None")
        assert_type(error.path_redacted, bool)
    except rookie_cookies.RookieRequestError as error:
        assert_type(error.required, List[str])
    except rookie_cookies.RookieEngineError as error:
        assert_type(error.code, "str | None")
    except rookie_cookies.RookieError as error:
        assert_type(error.kind, str)
        assert_type(error.profile_ids, List[str])


def platform_conditional_exports() -> None:
    """Platform-only browsers, guarded the way a real consumer guards them.

    The `sys.platform` *attribute* form is the one mypy and pyright narrow on;
    an alias bound by `from sys import platform` is just a `str` to both, so a
    guard written that way prunes nothing and every platform's exports stay
    visible everywhere. That is precisely the drift this function pins.
    """
    if sys.platform == "win32":
        assert_type(rookie_cookies.internet_explorer(), List[Dict[str, Any]])
        assert_type(rookie_cookies.octo_browser(["example.com"]), List[Dict[str, Any]])
        assert_type(rookie_cookies.opera_gx(), List[Dict[str, Any]])
    elif sys.platform == "darwin":
        assert_type(rookie_cookies.safari(["example.com"]), List[Dict[str, Any]])
        assert_type(rookie_cookies.opera_gx(), List[Dict[str, Any]])
    elif sys.platform.startswith("linux"):
        assert_type(rookie_cookies.cachy(["example.com"]), List[Dict[str, Any]])


def other_platforms_exports_are_hidden() -> None:
    """The negative half: a foreign platform's browser must NOT resolve here.

    Each reference below is on a platform where the name is absent, so mypy is
    expected to reject it and the ignore comment is expected to be *used*. If
    the package ever stops pruning by platform -- which is exactly what happens
    when a guard is written against a `from sys import platform` alias -- the
    name resolves, the ignore becomes unused, and `--strict`'s
    `--warn-unused-ignores` turns that into a build failure. A positive
    `assert_type` cannot catch this: on the wrong platform there is nothing to
    assert about.
    """
    if sys.platform == "darwin":
        rookie_cookies.cachy  # type: ignore[attr-defined]
        rookie_cookies.internet_explorer  # type: ignore[attr-defined]
        rookie_cookies.octo_browser  # type: ignore[attr-defined]
    elif sys.platform == "win32":
        rookie_cookies.cachy  # type: ignore[attr-defined]
        rookie_cookies.safari  # type: ignore[attr-defined]
    elif sys.platform.startswith("linux"):
        rookie_cookies.safari  # type: ignore[attr-defined]
        rookie_cookies.opera_gx  # type: ignore[attr-defined]
        rookie_cookies.internet_explorer  # type: ignore[attr-defined]


def cross_platform_exports() -> None:
    """Names that exist on every platform, including the deprecated pair."""
    assert_type(rookie_cookies.chrome(), List[Dict[str, Any]])
    assert_type(rookie_cookies.firefox(["example.com"]), List[Dict[str, Any]])
    assert_type(rookie_cookies.version(), str)
    assert_type(rookie_cookies.supported_browsers(), List[Dict[str, Any]])
    assert_type(rookie_cookies.MAX_ISSUE_SAMPLES, int)

    cookies = rookie_cookies.chromium_cookies_from_path("/nonexistent/Cookies")
    assert_type(cookies, List[Dict[str, Any]])
    assert_type(rookie_cookies.to_netscape(cookies), str)
    assert_type(rookie_cookies.to_cookiejar(cookies), http.cookiejar.CookieJar)
    assert_type(
        rookie_cookies.create_cookie(
            "example.com", "/", True, None, "sid", "value", True
        ),
        http.cookiejar.Cookie,
    )
