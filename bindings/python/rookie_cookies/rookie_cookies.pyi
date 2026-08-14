from sys import platform
from typing import Any, Dict, List, Optional

CookieList = List[Dict[str, Any]]
FirefoxProfile = Dict[str, Any]
FirefoxProfileList = List[FirefoxProfile]
BrowserDescriptor = Dict[str, Any]
BrowserDescriptorList = List[BrowserDescriptor]
ProfileDescriptor = Dict[str, Any]
ProfileDescriptorList = List[ProfileDescriptor]
ExtractionReport = Dict[str, Any]

MAX_ISSUE_SAMPLES: int
"""Upper bound on ``samples`` per issue.

``occurrences`` counts every occurrence while ``samples`` keeps at most this
many, so comparing the two tells a truncated excerpt from a complete one.
"""

def version() -> str:
    """
    Get the rookie-cookies version.

    :return: rookie-cookies version
    """
    ...

def firefox(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Firefox

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def firefox_profiles() -> FirefoxProfileList:
    """
    List Firefox profiles that contain a cookie database.

    Each dictionary contains ``name``, ``path``, and ``is_default``.
    """
    ...

def firefox_profile(
    profile: str, domains: Optional[List[str]] = None
) -> CookieList:
    """
    Extract cookies from a selected Firefox profile.

    :param profile: Profile name, directory name, or full path from firefox_profiles
    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def zen(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Zen

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def firefox_based(db_path: str, domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Firefox-based browsers

    :param db_path: Path to the database file
    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def brave(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Brave browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def edge(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Microsoft Edge browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def chrome(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Google Chrome browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

if platform == "win32":
    def chromium_based(
        key_path: str, db_path: str, domains: Optional[List[str]] = None
    ) -> CookieList:
        """
        Extract Cookies from Chromium-based browsers on Windows

        :param key_path: Path to the browser's Local State file
        :param db_path: Path to the database file
        :param domains: Optional list of domains to extract only from them
        :return: A list of dictionaries of cookies
        """
        ...
else:
    def chromium_based(db_path: str, domains: Optional[List[str]] = None) -> CookieList:
        """
        Extract Cookies from Chromium-based browsers on Unix

        :param db_path: Path to the database file
        :param domains: Optional list of domains to extract only from them
        :return: A list of dictionaries of cookies
        """
        ...

def chromium(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Chromium browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def arc(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Arc browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def opera(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Opera browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def vivaldi(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Vivaldi browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def opera_gx(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from Opera GX browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def librewolf(domains: Optional[List[str]] = None) -> CookieList:
    """
    Extract Cookies from LibreWolf browser

    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def load(domains: Optional[List[str]] = None) -> CookieList:
    """
    Load Cookies from a browser

    :param domains: Optional list of domains to load cookies from
    :return: A list of dictionaries of cookies
    """
    ...

def any_browser(
    db_path: str, domains: Optional[List[str]] = ..., key_path: Optional[str] = ...
) -> CookieList:
    """
    Extract Cookies from any browser.

    :param db_path: Path to browser database file.
    :param domains: Optional list of domains to extract cookies only from these domains.
    :param key_path: Optional path to key file used to decrypt `db_path`.
    :return: A list of dictionaries of cookies.
    """
    ...

def supported_browsers() -> BrowserDescriptorList:
    """
    List every browser registered for the running OS.

    Registration is not detection: a descriptor only means rookie knows where
    that browser would keep its cookies. Each dictionary contains ``id``,
    ``aliases``, ``display_name``, ``engine``, and ``capabilities``, itself a
    dictionary of ``persistent_formats``, ``session_formats``,
    ``declared_decryption_tiers``, and ``available_decryption_tiers``.

    :return: A list of browser descriptor dictionaries
    """
    ...

def browser_profiles(browser_id: str) -> ProfileDescriptorList:
    """
    List the discovered profiles of one registered browser.

    Each dictionary contains ``profile`` (``browser_id``, ``installation_id``,
    ``profile_id``, ``display_name``, ``path``, ``path_lossy``), ``is_default``,
    and ``sources`` (``role``, ``format``, ``path``, ``path_lossy``,
    ``precedence``). A known browser with nothing installed returns an empty
    list.

    :param browser_id: A canonical browser ID or alias from supported_browsers
    :return: A list of profile descriptor dictionaries
    :raises RuntimeError: The browser ID is unknown, or every detected
        installation root failed enumeration. The message is a diagnostic, not
        a stable contract; branch on the exception type instead.
    """
    ...

def chrome_profiles() -> ProfileDescriptorList:
    """
    List discovered Google Chrome profiles with the preferred active profile
    first.

    Missing, stale, or malformed Local State activity hints safely retain the
    generic default-first discovery order. Profile and source descriptor keys
    are the same as for ``browser_profiles``.
    """
    ...

def chrome_profile(
    profile: str, domains: Optional[List[str]] = None
) -> ExtractionReport:
    """
    Extract one selected Google Chrome profile as a grouped report.

    :param profile: Profile ID, display name, directory name, or full path from
        chrome_profiles when ``descriptor["profile"]["path_lossy"]`` is false.
        Use the profile ID for a lossy display path.
    :param domains: Optional list of domains to extract only from them
    :return: A report retaining profile identity, source provenance, and typed
        discovery/extraction issues
    :raises RuntimeError: The selector is missing or ambiguous, or discovery
        changed before extraction. The message is diagnostic, not stable.
    """
    ...

def browser_report(
    browser_id: str,
    profile_id: Optional[str] = None,
    domains: Optional[List[str]] = None,
) -> ExtractionReport:
    """
    Extract cookies from one browser as a grouped report.

    The report contains ``status``, ``summary``, ``profiles``, and ``issues``.
    Cookies stay attached to the source they came from, alongside that source's
    ``status``, ``selected`` flag, ``acquisition_strategy``, ``stats``, and
    ``issues``. An absent browser is a report with status ``no_sources``, and a
    failure during extraction is an issue rather than an exception.

    :param browser_id: A canonical browser ID or alias from supported_browsers
    :param profile_id: Optional profile_id from browser_profiles, restricting
        the report to that one profile
    :param domains: Optional list of domains to extract only from them
    :return: An extraction report dictionary
    :raises RuntimeError: The request itself is bad -- an unknown browser ID,
        or a profile ID this browser did not yield. The message is a
        diagnostic, not a stable contract; branch on the exception type
        instead.
    """
    ...

def load_report(domains: Optional[List[str]] = None) -> ExtractionReport:
    """
    Extract cookies from every registered browser as one grouped report.

    :param domains: Optional list of domains to extract only from them
    :return: An extraction report dictionary
    """
    ...

# Windows
if platform == "win32":
    def internet_explorer(domains: Optional[List[str]] = None) -> CookieList:
        """
        Extract Cookies from Internet Explorer

        :param domains: Optional list of domains to extract only from them
        :return: A list of dictionaries of cookies
        """
        ...

    def octo_browser(domains: Optional[List[str]] = None) -> CookieList:
        """
        Extract Cookies from Octo browser

        :param domains: Optional list of domains to extract only from them
        :return: A list of dictionaries of cookies
        """
        ...

# MacOS
if platform == "darwin":
    def safari(domains: Optional[List[str]] = None) -> CookieList:
        """
        Extract Cookies from Safari browser

        :param domains: Optional list of domains to extract only from them
        :return: A list of dictionaries of cookies
        """
        ...
