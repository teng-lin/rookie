import http.cookiejar
from sys import platform
from typing import Any, Dict, List, Optional, TypedDict

from .rookie_cookies import (
    MAX_ISSUE_SAMPLES,
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
    firefox,
    firefox_based,
    firefox_based_detailed,
    firefox_profile,
    firefox_profiles,
    librewolf,
    load,
    load_report,
    opera,
    supported_browsers,
    version,
    vivaldi,
    zen,
)

__all__ = [
    "MAX_ISSUE_SAMPLES",
    "ChromiumPathOptions",
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
    "firefox",
    "firefox_based",
    "firefox_based_detailed",
    "firefox_profile",
    "firefox_profiles",
    "librewolf",
    "load",
    "load_report",
    "opera",
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
