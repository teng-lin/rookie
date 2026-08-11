from sys import platform
from typing import Any, Dict, List, Optional

CookieList = List[Dict[str, Any]]
FirefoxProfile = Dict[str, Any]
FirefoxProfileList = List[FirefoxProfile]

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
