import http.cookiejar
from sys import platform
from typing import Any, Dict, List, Optional, TypedDict

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
    "opera",
    "profiles",
    "read",
    "report",
    "supported_browsers",
    "to_cookiejar",
    "to_netscape",
    "version",
    "vivaldi",
    "zen",
]


class ChromiumPathOptions(TypedDict, total=False):
    domains: list[str]
    browser_id: str
    local_state_path: str
    plaintext_only: bool
    timeout: float
    cancellation: CancellationHandle
    app_bound: str


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
if platform == "win32":
    from .rookie_cookies import (
        internet_explorer as internet_explorer,
    )
    from .rookie_cookies import (
        octo_browser as octo_browser,
    )
    from .rookie_cookies import opera_gx as opera_gx

    __all__.extend(["internet_explorer", "octo_browser", "opera_gx"])


# macOS
if platform == "darwin":
    from .rookie_cookies import opera_gx as opera_gx
    from .rookie_cookies import safari as safari

    __all__.extend(["opera_gx", "safari"])


# Linux
if platform.startswith("linux"):
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


def _read_result_as_jar(self: ReadResult) -> http.cookiejar.CookieJar:
    return to_cookiejar(self.as_list())


ReadResult.as_jar = _read_result_as_jar  # type: ignore[method-assign]


def jar(
    *,
    browser: str,
    profile: Optional[str] = None,
    include_expired: bool = False,
    include_session: bool = False,
    select: str = "legacy_first",
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: str = "disabled",
) -> http.cookiejar.CookieJar:
    """
    Sugar: ``read(...).as_jar()``. Warnings are discarded; use ``read()`` if you need them.

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
    ).as_jar()


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
    select: Optional[str] = None,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: str = "disabled",
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


def to_cookiejar(cookies: CookieList) -> http.cookiejar.CookieJar:
    """
    Convert a list of dictionaries representing cookies to a CookieJar.

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
