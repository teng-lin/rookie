import http.cookiejar
import sys
from typing import Any, Dict, List, Literal, Optional, TypedDict

from . import dto as dto
from .rookie_cookies import (
    MAX_ISSUE_SAMPLES,
    CancellationHandle,
    ReadResult,
    ReadWarning,
    RookieEngineError,
    RookieError,
    RookieRequestError,
    RookieSourceError,
    RookieStoppedError,
    any_browser,
    arc,
    brave,
    browser_profiles,
    browser_report,
    chrome,
    chrome_profile,
    chrome_profiles,
    chromium,
    chromium_based,
    chromium_based_detailed,
    chromium_cookies_from_path,
    chromium_cookies_from_path_detailed,
    cookies_from_path,
    edge,
    extract_from_path,
    firefox,
    firefox_based,
    firefox_based_detailed,
    firefox_profile,
    firefox_profiles,
    from_path,
    librewolf,
    load,
    load_report,
    opera,
    read,
    supported_browsers,
    version,
    vivaldi,
    zen,
)

__all__ = [
    "MAX_ISSUE_SAMPLES",
    "CancellationHandle",
    "ChromiumPathOptions",
    "AppBoundPolicy",
    "ReportProfileSelection",
    "SingleProfileSelection",
    "ReadResult",
    "ReadWarning",
    "RookieEngineError",
    "RookieError",
    "RookieRequestError",
    "RookieSourceError",
    "RookieStoppedError",
    "dto",
    "any_browser",
    "arc",
    "brave",
    "browser_profiles",
    "browser_report",
    "chrome",
    "chrome_profile",
    "chrome_profiles",
    "chromium",
    "chromium_based",
    "chromium_based_detailed",
    "chromium_cookies_from_path",
    "chromium_cookies_from_path_detailed",
    "cookies_from_path",
    "create_cookie",
    "edge",
    "extract_from_path",
    "firefox",
    "firefox_based",
    "firefox_based_detailed",
    "firefox_profile",
    "firefox_profiles",
    "from_path",
    "jar",
    "librewolf",
    "load",
    "load_report",
    "load_report_dto",
    "opera",
    "profiles",
    "profiles_dto",
    "read",
    "report",
    "report_dto",
    "supported_browsers",
    "supported_browsers_dto",
    "to_cookiejar",
    "to_netscape",
    "version",
    "vivaldi",
    "zen",
]

AppBoundPolicy = Literal["disabled", "injection_only", "allow_elevated_fallback"]
SingleProfileSelection = Literal["legacy_first"]
ReportProfileSelection = Literal["legacy_first", "all"]


class ChromiumPathOptions(TypedDict, total=False):
    domains: list[str]
    browser_id: str
    local_state_path: str
    plaintext_only: bool
    timeout: float
    cancellation: CancellationHandle
    app_bound: AppBoundPolicy


CookieList = List[Dict[str, Any]]
DetailedCookieList = List[Dict[str, Any]]
FirefoxProfile = Dict[str, Any]
FirefoxProfileList = List[FirefoxProfile]
BrowserDescriptor = Dict[str, Any]
BrowserDescriptorList = List[BrowserDescriptor]
ProfileDescriptor = Dict[str, Any]
ProfileDescriptorList = List[ProfileDescriptor]
ExtractionReport = Dict[str, Any]


# Windows
if sys.platform == "win32":
    from .rookie_cookies import (
        internet_explorer as internet_explorer,
    )
    from .rookie_cookies import (
        octo_browser as octo_browser,
    )
    from .rookie_cookies import opera_gx as opera_gx

    __all__.extend(["internet_explorer", "octo_browser", "opera_gx"])


# macOS
if sys.platform == "darwin":
    from .rookie_cookies import opera_gx as opera_gx
    from .rookie_cookies import safari as safari

    __all__.extend(["opera_gx", "safari"])


# Linux
if sys.platform.startswith("linux"):
    from .rookie_cookies import cachy as cachy

    __all__.append("cachy")


def create_cookie(
    host: str,
    path: str,
    secure: bool,
    expires: Optional[int],
    name: str,
    value: Optional[str],
    http_only: bool,
) -> http.cookiejar.Cookie:
    """
    Create a Cookie object with the specified attributes.

    :param str host: The domain for which the cookie is valid
    :param str path: The path within the domain for which the cookie is valid
    :param bool secure: True if the cookie should only be sent over secure connections (HTTPS)
    :param Optional[int] expires: Unix timestamp indicating when the cookie expires
    :param str name: The name of the cookie
    :param Optional[str] value: The value of the cookie
    :param bool http_only: True if the cookie should only be accessible via HTTP and not JavaScript
    :return: A Cookie object
    :rtype: http.cookiejar.Cookie
    """
    # HTTPOnly flag goes in _rest, if present (see https://github.com/python/cpython/pull/17471/files#r511187060)
    return http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=host,
        domain_specified=host.startswith("."),
        domain_initial_dot=host.startswith("."),
        path=path,
        path_specified=True,
        secure=secure,
        expires=expires,
        discard=expires is None,
        comment=None,
        comment_url=None,
        rest={"HTTPOnly": ""} if http_only else {},
    )


def _read_result_as_jar(
    self: ReadResult, *, allow_isolation_loss: bool = False
) -> http.cookiejar.CookieJar:
    """Load this snapshot into an ``http.cookiejar.CookieJar``.

    Routed through ``compatibility_cookies`` rather than ``as_list()``: a
    ``CookieJar`` has no field for a CHIPS partition key, a Firefox
    ``partitionKey`` tuple, or container identity, so building one from an
    isolated snapshot would turn context-scoped credentials into unscoped
    ones with no error and no visible difference. It refuses instead, with
    ``code == "isolation_loss_refused"`` and a ``required`` list naming the
    selectors a ``send_view()`` / ``header()`` call would need.

    :param allow_isolation_loss: Build the jar anyway. Output is identical to
        what this returned before the refusal existed.
    """
    return to_cookiejar(
        self.compatibility_cookies(allow_isolation_loss=allow_isolation_loss)
    )


ReadResult.as_jar = _read_result_as_jar  # type: ignore[method-assign]


def jar(
    *,
    browser: str,
    profile: Optional[str] = None,
    include_expired: bool = False,
    include_session: bool = False,
    select: SingleProfileSelection = "legacy_first",
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
    allow_isolation_loss: bool = False,
) -> http.cookiejar.CookieJar:
    """
    Sugar: ``read(...).as_jar()``. Warnings are discarded; use ``read()`` if you need them.

    **Fails closed on isolation loss (0.7).** A ``CookieJar`` cannot represent
    a CHIPS partition key or a Firefox container identity, so a snapshot that
    holds any isolated cookie raises ``RookieRequestError`` with
    ``code == "isolation_loss_refused"`` rather than flattening it. The error's
    ``required`` list names the selectors ``ReadResult.send_view()`` /
    ``header()`` would need for that snapshot. Pass
    ``allow_isolation_loss=True`` to accept the loss; an unisolated snapshot
    is unaffected and keeps working exactly as before.

    **Migration trap:** ``include_session`` defaults to ``False``. In 0.6-beta,
    ``jar(profile="Default")`` imported that profile's session cookies too;
    it does not in 0.6.0 unless ``include_session=True`` is also passed. This
    fails quietly -- a smaller jar, no error -- so code relying on session
    cookies riding along with a Gecko ``profile=`` selector needs this flag
    added explicitly::

        session_jar = jar(
            browser="firefox", profile="default-release", include_session=True
        )

    See CHANGELOG.md.
    """
    return read(
        browser=browser,
        profile=profile,
        include_expired=include_expired,
        include_session=include_session,
        select=select,
        timeout=timeout,
        cancellation=cancellation,
        app_bound=app_bound,
    ).as_jar(allow_isolation_loss=allow_isolation_loss)


def profiles(
    browser_id: str,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> ProfileDescriptorList:
    """Alias of :func:`browser_profiles`."""
    return browser_profiles(browser_id, timeout=timeout, cancellation=cancellation)


def report(
    browser: str,
    *,
    profile: Optional[str] = None,
    domains: Optional[List[str]] = None,
    select: Optional[ReportProfileSelection] = None,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> ExtractionReport:
    """Bindings name for :func:`browser_report` / Rust ``extract_report``.

    ``select`` defaults to ``None``, not ``"all"``. Its *effective* default is
    ``"all"``, but ``browser_report`` has to tell an omitted selection apart
    from an explicit ``select="all"`` -- the latter contradicts ``profile`` and
    raises ``conflicting_profile_selection``. Materializing the default here
    would make the ordinary ``report(browser=..., profile=...)`` call look like
    that contradiction.
    """
    return browser_report(
        browser,
        profile,
        domains,
        select=select,
        timeout=timeout,
        cancellation=cancellation,
        app_bound=app_bound,
    )


def supported_browsers_dto() -> List[dto.BrowserDescriptor]:
    """Typed dataclass view of :func:`supported_browsers`."""
    return [dto.BrowserDescriptor.from_dict(item) for item in supported_browsers()]


def profiles_dto(
    browser_id: str,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> List[dto.ProfileDescriptor]:
    """Typed dataclass view of :func:`profiles`."""
    return [
        dto.ProfileDescriptor.from_dict(item)
        for item in profiles(browser_id, timeout=timeout, cancellation=cancellation)
    ]


def report_dto(
    browser: str,
    *,
    profile: Optional[str] = None,
    domains: Optional[List[str]] = None,
    select: Optional[ReportProfileSelection] = None,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> dto.ExtractionReport:
    """Typed dataclass view of :func:`report`."""
    return dto.ExtractionReport.from_dict(
        report(
            browser,
            profile=profile,
            domains=domains,
            select=select,
            timeout=timeout,
            cancellation=cancellation,
            app_bound=app_bound,
        )
    )


def load_report_dto(
    domains: Optional[List[str]] = None,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> dto.ExtractionReport:
    """Typed dataclass view of :func:`load_report`."""
    return dto.ExtractionReport.from_dict(
        load_report(
            domains,
            timeout=timeout,
            cancellation=cancellation,
            app_bound=app_bound,
        )
    )


def to_cookiejar(cookies: CookieList) -> http.cookiejar.CookieJar:
    """
    Convert a list of dictionaries representing cookies to a CookieJar.

    A pure function over rows you already hold; it applies no isolation
    policy of its own. The fail-closed paths are ``ReadResult.as_jar()`` and
    ``ReadResult.compatibility_cookies()`` — reach for those when the rows
    come from a snapshot, since only they know whether the snapshot held
    isolated cookies a ``CookieJar`` cannot represent.

    :param cookies: A list of dictionaries representing cookies
    :return: A CookieJar containing the converted cookies
    """
    cj = http.cookiejar.CookieJar()

    for cookie_obj in cookies:
        c = create_cookie(
            cookie_obj["domain"],
            cookie_obj["path"],
            cookie_obj["secure"],
            cookie_obj["expires"],
            cookie_obj["name"],
            cookie_obj["value"],
            cookie_obj["http_only"],
        )
        cj.set_cookie(c)
    return cj


def to_netscape(cookies: CookieList) -> str:
    """
    Convert a list of dictionaries representing cookies to a netscape compatible string.

    Tabs, carriage returns, and line feeds in cookie-controlled fields are
    percent-encoded. Hash signs are encoded only in the domain field, where a
    leading ``#`` would become a comment or forged HttpOnly marker.

    A pure function over rows you already hold; it applies no isolation
    policy of its own. A Netscape file has no column for a partition key, so
    feed it ``ReadResult.compatibility_cookies()`` (which refuses, or takes
    an explicit ``allow_isolation_loss=True``) rather than ``as_list()``
    when the rows come from a possibly-isolated snapshot.

    :param cookies: A list of dictionaries representing cookies
    :return: A string containing the converted cookies
    """
    data = f"""\
# Netscape HTTP Cookie File
# Generated by rookie-cookies {version()}
# Edit at your own risk.\n\n"""

    for cookie in cookies:
        domain = _escape_netscape_domain(cookie["domain"])
        if cookie["http_only"]:
            domain = f"#HttpOnly_{domain}"
        subdomain = repr(cookie["domain"].startswith(".")).upper()
        https_only = repr(cookie["secure"]).upper()
        path = _escape_netscape_field(cookie["path"])
        name = _escape_netscape_field(cookie["name"])
        value = _escape_netscape_field(cookie["value"])
        expires = _escape_netscape_field(cookie["expires"] if cookie["expires"] else 0)
        data += (
            f"{domain}\t{subdomain}\t{path}\t{https_only}\t{expires}\t"
            f"{name}\t{value}\n"
        )

    return data


def _escape_netscape_field(field: Any) -> str:
    return (
        str(field)
        .replace("\t", "%09")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _escape_netscape_domain(domain: Any) -> str:
    return _escape_netscape_field(domain).replace("#", "%23")
