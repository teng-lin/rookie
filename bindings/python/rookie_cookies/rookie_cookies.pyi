import http.cookiejar
import sys
from typing import Any, Dict, List, Literal, Optional, TypedDict

from . import dto as dto

CookieList = List[Dict[str, Any]]
AppBoundPolicy = Literal["disabled", "injection_only", "allow_elevated_fallback"]
SingleProfileSelection = Literal["legacy_first"]
ReportProfileSelection = Literal["legacy_first", "all"]

class CookieObject(TypedDict):
    domain: str
    path: str
    secure: bool
    expires: Optional[int]
    name: str
    value: str
    http_only: bool
    same_site: int

class CookieContext(TypedDict):
    top_frame_site_key: Optional[str]
    has_cross_site_ancestor: Optional[bool]
    source_scheme: Optional[int]
    source_port: Optional[int]
    is_persistent: Optional[bool]
    origin_attributes: Optional[str]
    user_context_id: Optional[int]
    partition_key: Optional[str]
    private_browsing_id: Optional[int]

class DetailedCookie(TypedDict):
    cookie: CookieObject
    context: CookieContext

class SendContextMapping(TypedDict, total=False):
    """Mapping form of ``ReadResult.header``'s positional ``context`` argument."""

    url: str
    top_level_site: str
    resource: Literal["navigation", "subresource"]
    method: Literal["safe", "unsafe"]
    user_context_id: int
    private_browsing_id: int
    now: float

class ChromiumPathOptions(TypedDict, total=False):
    domains: list[str]
    browser_id: str
    local_state_path: str
    plaintext_only: bool
    timeout: float
    cancellation: "CancellationHandle"
    app_bound: AppBoundPolicy

class CancellationHandle:
    """
    A shared stop signal for an in-flight extraction.

    Calling ``cancel()`` from any thread stops the extraction this handle was
    passed into at its next internal checkpoint. Cloning (e.g. holding the
    same instance from multiple threads) shares the same underlying signal.
    """

    def __init__(self) -> None: ...
    def cancel(self) -> bool: ...
    def is_cancelled(self) -> bool: ...

class RookieError(Exception):
    """
    Common base for every exception this module raises. Catch this to handle
    any rookie_cookies failure without distinguishing its kind.
    """
    # Open string: "request", "stopped", "source", or "engine" today, but new
    # kinds can appear in a future release without a type-checking break.
    kind: str
    code: str | None
    # Current values: "timed_out", "cancelled", and "resource_exhausted".
    # This remains an open string so future native stop reasons are representable.
    stop_reason: str | None
    profile_ids: list[str]
    source_kind: str | None
    target_os: str | None
    path_redacted: bool
    # The SendContext selectors header() needed but did not receive (e.g.
    # ["top_level_site"]). Empty for every kind except "request" with
    # code "incomplete_send_context".
    required: list[str]

class RookieRequestError(RookieError, ValueError):
    """
    The caller's input was invalid -- an unsupported option or an explicit
    source that does not match its declared kind. Fixable by changing what
    was passed in.
    """
    kind: Literal["request"]

class RookieStoppedError(RookieError, RuntimeError):
    """
    The operation stopped cooperatively before producing a result: a timeout
    elapsed, a CancellationHandle was cancelled, or an internal resource
    limit was reached. See the ``stop_reason`` attribute.
    """
    kind: Literal["stopped"]

class RookieSourceError(RookieRequestError):
    """
    A caller-supplied path or path option was invalid -- an explicit source
    that does not exist, does not match its declared kind, or is not
    supported on this platform. Subclasses RookieRequestError/ValueError
    (rather than sitting beside it under RookieError) so an
    ``except RookieRequestError`` or ``except ValueError`` written before
    this class existed keeps catching a direct-path fault.
    """
    # Narrowing a base class's Literal is only sound for a read-only member,
    # and this one is writable: bindings/python/src/errors.rs sets it with
    # `value.setattr("kind", ...)`, not as a property. The precise Literal is
    # worth more at a call site than the invariance it violates, so the
    # override is kept and the ignore is the price.
    kind: Literal["source"]  # type: ignore[assignment]

class RookieEngineError(RookieError, RuntimeError):
    """Extraction, source inspection, or engine failure unrelated to caller input."""
    kind: Literal["engine"]

DetailedCookieList = List[DetailedCookie]
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

def extract_from_path(
    path: str,
    *,
    domains: Optional[List[str]] = None,
    plaintext_only: bool = False,
    browser_id: Optional[str] = None,
    local_state_path: Optional[str] = None,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> CookieList:
    """
    Extract cookies from an explicit cookie file.

    The canonical name for this job (Rust ``direct_path::extract_from_path``,
    Node ``extractFromPath``, CLI ``from-path --domains``).
    ``cookies_from_path`` and ``chromium_cookies_from_path`` remain as
    deprecated aliases onto this function.

    By default the source is identified automatically: a Mozilla / Safari /
    Internet Explorer store needs no credential, and an encrypted Chromium
    row is ``missing_chromium_credentials`` rather than a guess at which
    browser wrote it. At most one of ``plaintext_only``, ``browser_id``,
    ``local_state_path`` may be given.

    **Windows App-Bound (v20):** ``app_bound`` defaults to ``"injection_only"`` -- see ``read``'s
    docstring; the same default and the same values apply here.

    :param domains: Optional list of domains to extract only from them
    :param plaintext_only: Reject the whole request if any Chromium row is
        encrypted, rather than guessing a credential for it
    :param browser_id: Registry browser identity for an encrypted Chromium
        database (Linux keyring / macOS Keychain). Unix only.
    :param local_state_path: Path to a Chromium ``Local State`` file, for an
        encrypted Chromium database. Windows only.
    :param timeout: Optional extraction budget in seconds
    :param cancellation: Optional handle whose ``cancel()`` stops extraction early
    :param app_bound: Windows App-Bound (v20) recovery policy: "injection_only"
        (default), "disabled", or "allow_elevated_fallback". A no-op
        off Windows.
    :raises RookieRequestError: More than one credential selector was given
        (``conflicting_credential_selectors``), a platform-incompatible one,
        or an unrecognized ``app_bound`` value
    :raises RookieEngineError: Source inspection failed due to an I/O, SQLite,
        locked, or corrupt-file failure (``source_inspection_failed``), or
        extraction failed after classification
    """
    ...

def cookies_from_path(
    path: str,
    domains: list[str] | None = None,
    timeout: float | None = None,
    cancellation: CancellationHandle | None = None,
) -> CookieList:
    """
    Classify an explicit cookie source and extract its cookies.

    **Deprecated: use** :func:`extract_from_path` **instead.** Identical to
    calling it with no ``plaintext_only`` / ``browser_id`` / ``local_state_path``.

    :param timeout: Optional extraction budget in seconds
    :param cancellation: Optional handle whose ``cancel()`` stops extraction early
    """
    ...

def chromium_cookies_from_path(
    path: str, options: ChromiumPathOptions | None = None
) -> CookieList:
    """
    Extract an explicit Chromium cookie database.

    **Deprecated: use** :func:`extract_from_path` **instead**, which takes
    the same options as flat keyword arguments rather than a dict.

    ``options`` may set ``timeout`` (seconds) and ``cancellation`` (a
    :class:`CancellationHandle`) to bound or stop extraction early.
    """
    ...

def chromium_cookies_from_path_detailed(
    path: str, options: ChromiumPathOptions | None = None
) -> DetailedCookieList:
    """
    Extract an explicit Chromium database with cookie context.

    **Deprecated: no direct replacement of the same shape.** Isolation-aware
    path output now comes from ``from_path(..).detailed_cookies()``, which
    has no ``domains`` filter of its own.

    ``options`` may set ``timeout`` (seconds) and ``cancellation`` (a
    :class:`CancellationHandle`) to bound or stop extraction early.

    **``options["domains"]`` is no longer accepted** and raises
    ``RookieRequestError`` if given. Isolation-aware output now comes from
    the core's ``from_path(..).detailed_cookies()``, which has no domain
    filter of its own -- a real narrowing, not a binding limitation. Use
    ``chromium_cookies_from_path`` for a domain-filtered flat list, or filter
    this function's output yourself. See CHANGELOG.md.
    """
    ...

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

    .. deprecated:: 0.6
       Use ``cookies_from_path``. Earliest removal is 0.7.

    :param db_path: Path to the database file
    :param domains: Optional list of domains to extract only from them
    :return: A list of dictionaries of cookies
    """
    ...

def firefox_based_detailed(
    db_path: str, domains: Optional[List[str]] = None
) -> DetailedCookieList:
    """Extract cookies with Firefox container and origin context preserved."""
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

if sys.platform == "win32":
    def chromium_based(
        key_path: str, db_path: str, domains: Optional[List[str]] = None
    ) -> CookieList:
        """
        Extract Cookies from Chromium-based browsers on Windows

        .. deprecated:: 0.6
           Use ``chromium_cookies_from_path``. Earliest removal is 0.7.

        :param key_path: Path to the browser's Local State file
        :param db_path: Path to the database file
        :param domains: Optional list of domains to extract only from them
        :return: A list of dictionaries of cookies
        """
        ...
    def chromium_based_detailed(
        key_path: str, db_path: str, domains: Optional[List[str]] = None
    ) -> DetailedCookieList:
        """Deprecated: use ``chromium_cookies_from_path_detailed`` before 0.7."""
        ...
else:
    def chromium_based(
        db_path: str,
        domains: Optional[List[str]] = None,
        browser_id: Optional[str] = None,
    ) -> CookieList:
        """
        Extract Cookies from Chromium-based browsers on Unix

        .. deprecated:: 0.6
           Use ``chromium_cookies_from_path``. Earliest removal is 0.7.

        :param db_path: Path to the database file
        :param domains: Optional list of domains to extract only from them
        :param browser_id: Canonical browser identity for encrypted profiles
        :return: A list of dictionaries of cookies
        """
        ...
    def chromium_based_detailed(
        db_path: str,
        domains: Optional[List[str]] = None,
        browser_id: Optional[str] = None,
    ) -> DetailedCookieList:
        """Deprecated: use ``chromium_cookies_from_path_detailed`` before 0.7."""
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

    .. deprecated:: 0.6
       Use ``cookies_from_path`` or ``chromium_cookies_from_path``. Earliest
       removal is 0.7.

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

    This does no disk I/O, so unlike every other function in this module it
    takes no ``timeout`` / ``cancellation`` / ``app_bound``.

    :return: A list of browser descriptor dictionaries
    """
    ...

def browser_profiles(
    browser_id: str,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> ProfileDescriptorList:
    """
    List the discovered profiles of one registered browser.

    Each dictionary contains ``profile`` (``browser_id``, ``installation_id``,
    ``profile_id``, ``display_name``, ``path``, ``path_lossy``), ``is_default``,
    and ``sources`` (``role``, ``format``, ``path``, ``path_lossy``,
    ``precedence``). A known browser with nothing installed returns an empty
    list.

    Listing does no Windows App-Bound recovery, so unlike ``read`` /
    ``browser_report`` / ``load_report`` this takes no ``app_bound`` parameter.

    :param browser_id: A canonical browser ID or alias from supported_browsers
    :param timeout: Optional timeout in seconds
    :param cancellation: Optional CancellationHandle
    :return: A list of profile descriptor dictionaries
    :raises RookieRequestError: The browser ID is unknown.
    :raises RookieEngineError: Every detected installation root failed
        enumeration. Messages are diagnostic, not a stable contract; branch
        on the exception type instead.
    """
    ...

def chrome_profiles(
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> ProfileDescriptorList:
    """
    List discovered Google Chrome profiles with the preferred active profile
    first.

    Missing, stale, or malformed Local State activity hints safely retain the
    generic default-first discovery order. Profile and source descriptor keys
    are the same as for ``browser_profiles``. Listing does no Windows
    App-Bound recovery, so this takes no ``app_bound`` parameter.
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
    :raises RookieRequestError: The selector is missing or ambiguous.
    :raises RookieEngineError: Discovery or extraction failed after selection.
        The message is diagnostic, not stable.
    """
    ...

def browser_report(
    browser_id: str,
    profile_id: Optional[str] = None,
    domains: Optional[List[str]] = None,
    *,
    select: ReportProfileSelection = "all",
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> ExtractionReport:
    """
    Extract cookies from one browser as a grouped report.

    The report contains ``status``, ``summary``, ``profiles``, and ``issues``.
    Cookies stay attached to the source they came from, alongside that source's
    ``status``, ``selected`` flag, ``acquisition_strategy``, ``stats``, and
    ``issues``. An absent browser is a report with status ``no_sources``, and a
    failure during extraction is an issue rather than an exception.

    **Windows App-Bound (v20):** ``app_bound`` defaults to ``"injection_only"`` -- see ``read``'s
    docstring; the same default and the same values apply here.

    :param browser_id: A canonical browser ID or alias from supported_browsers
    :param profile_id: Optional profile_id from browser_profiles, restricting
        the report to that one profile
    :param domains: Optional list of domains to extract only from them
    :param select: Profile selection strategy when ``profile_id`` is not
        given: ``"all"`` (default) reports every installation and profile --
        what ``browser_report(id, None, domains)`` has always meant -- or
        ``"legacy_first"`` narrows the report to the first legacy-eligible
        profile, same as the named v0.5.9 helpers. Ignored when ``profile_id``
        is given, since a named profile already narrows to one.
    :param timeout: Optional timeout in seconds
    :param cancellation: Optional CancellationHandle
    :param app_bound: Windows App-Bound (v20) recovery policy: "injection_only"
        (default), "disabled", or "allow_elevated_fallback". A no-op
        off Windows.
    :return: An extraction report dictionary
    :raises RookieRequestError: The request itself is bad -- an unknown
        browser ID, a profile ID this browser did not yield, an unrecognized
        ``app_bound``/``select`` value, or ``profile_id`` given together with
        ``select="all"`` (``conflicting_profile_selection`` -- naming one
        profile and asking for every profile contradict each other). The
        message is a diagnostic, not a stable contract; branch on the
        exception type instead.
    """
    ...

def load_report(
    domains: Optional[List[str]] = None,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> ExtractionReport:
    """
    Extract cookies from every registered browser as one grouped report.

    **Windows App-Bound (v20):** ``app_bound`` defaults to ``"injection_only"`` -- see ``read``'s
    docstring; the same default and the same values apply here, for every
    browser in the fan-out.

    :param domains: Optional list of domains to extract only from them
    :param timeout: Optional timeout in seconds, shared by the whole fan-out
    :param cancellation: Optional CancellationHandle, shared by the whole fan-out
    :param app_bound: Windows App-Bound (v20) recovery policy: "injection_only"
        (default), "disabled", or "allow_elevated_fallback". A no-op
        off Windows.
    :return: An extraction report dictionary
    """
    ...

class ReadWarning:
    """Structured snapshot warning. ``code`` + ``count`` are the machine contract."""

    code: str
    count: int
    def __str__(self) -> str: ...

class ReadResult:
    """Unfiltered snapshot of one profile or one file. Never URL-pre-sliced."""

    warnings: list[ReadWarning]
    # None for from_path: it does not pass through browser discovery, so
    # there is no registry identity to report (changed in 0.6.0; used to be
    # the empty string, an in-band sentinel).
    browser_id: Optional[str]
    profile_id: Optional[str]
    def as_list(self) -> CookieList:
        """Eight-key cookie dicts matching ``chrome()`` / ``load()``."""
        ...
    def as_jar(self) -> "http.cookiejar.CookieJar":
        """Load every acquired record into ``http.cookiejar``. Not send-filtered."""
        ...
    def detailed_cookies(self) -> DetailedCookieList:
        """
        Isolation-intact records: each item is ``{"cookie": <8-field dict>,
        "context": <CookieContext dict>}``. Recommended over ``as_list()`` /
        the eight-field projection whenever CHIPS partitioning or a Firefox
        container matters, since that projection cannot represent either.
        """
        ...
    def header(
        self,
        context: "str | SendContextMapping | None" = None,
        /,
        *,
        url: Optional[str] = None,
        top_level_site: Optional[str] = None,
        resource: Optional[Literal["navigation", "subresource"]] = None,
        method: Optional[Literal["safe", "unsafe"]] = None,
        user_context_id: Optional[int] = None,
        private_browsing_id: Optional[int] = None,
        now: Optional[float] = None,
    ) -> str:
        """
        Cookie request-header view over this snapshot.

        ``context`` is positional-only and accepts either a plain URL string
        (equivalent to ``url=...`` -- every other field defaults) or a mapping
        with the same keys as the keyword arguments below. An explicit keyword
        argument always wins over a same-named mapping entry, so
        ``header({"url": u}, top_level_site=t)`` composes rather than
        conflicting. At least one of ``context`` or ``url=`` must supply a URL.

        :param context: A URL string, or a mapping of the keyword arguments below
        :param url: The request URL (http/https only)
        :param top_level_site: The top-level site the request is made from.
            Required as soon as the snapshot holds any CHIPS-partitioned cookie.
        :param resource: "navigation" or "subresource" (default)
        :param method: "safe" (default) or "unsafe"
        :param user_context_id: Firefox Multi-Account Containers identity
        :param private_browsing_id: Firefox private-browsing identity
        :param now: Epoch seconds overriding the send-time clock (default: now)
        :raises RookieRequestError: An invalid/missing URL or top-level site
            (``invalid_url`` / ``invalid_top_level_site``), an unrepresentable
            clock (``clock_unrepresentable``), or a snapshot that positively
            observes an isolated value ``context`` did not select
            (``incomplete_send_context`` -- see the ``required`` attribute for
            which selectors were missing)
        """
        ...
    def __iter__(self): ...
    def __len__(self) -> int: ...
    def __bool__(self) -> bool: ...

def read(
    *,
    browser: str,
    profile: Optional[str] = None,
    include_expired: bool = False,
    include_session: bool = False,
    select: SingleProfileSelection = "legacy_first",
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> ReadResult:
    """
    Read an unfiltered snapshot of one browser profile.

    **Windows App-Bound (v20):** ``app_bound`` defaults to
    ``"injection_only"``, which recovers a Chrome v20 profile without
    elevation by spawning a browser process and injecting into it. Endpoint
    security products can flag that, so pass ``"disabled"`` if it is
    unwanted -- v20 rows are then skipped and reported as ``decrypt_failed``
    warnings. ``"allow_elevated_fallback"`` additionally permits SYSTEM
    impersonation and is never the default. See CHANGELOG.md.

    **Migration trap:** ``include_session`` defaults to ``False``. In
    0.6-beta, naming a Gecko ``profile`` always imported its session cookies
    too; naming one here does not, unless ``include_session=True`` is also
    passed. This fails quietly -- a smaller snapshot, no error. See
    CHANGELOG.md.

    :param browser: Canonical browser ID or registered alias
    :param profile: Optional profile id, display name, directory, or path
    :param include_session: Also acquire the browser's declared session store
        (Gecko only; a no-op for Chromium, which declares none). Default false.
    :param select: Profile selection strategy. Only ``"legacy_first"`` (the
        default) is valid here -- ``"all"`` has nowhere to put more than one
        profile in a single snapshot; see ``browser_report`` for that.
    :param app_bound: Windows App-Bound (v20) recovery policy: "injection_only"
        (default), "disabled", or "allow_elevated_fallback". A no-op
        off Windows.
    :raises TypeError: ``browser`` was omitted
    :raises RookieRequestError: Unknown browser, profile selector, or
        ``app_bound`` value; or ``select`` was not ``"legacy_first"``
        (``conflicting_profile_selection``)
    """
    ...

def from_path(
    path: str,
    *,
    include_expired: bool = False,
    plaintext_only: bool = False,
    browser_id: Optional[str] = None,
    local_state_path: Optional[str] = None,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> ReadResult:
    """
    Read cookies from an explicit cookie database path.

    **Windows App-Bound (v20):** ``app_bound`` defaults to ``"injection_only"`` -- see ``read``'s
    docstring; the same default and the same values apply here.

    By default the source is identified automatically: a Mozilla / Safari /
    Internet Explorer store needs no credential, and an encrypted Chromium
    row is ``missing_chromium_credentials`` rather than a guess at which
    browser wrote it. At most one of ``plaintext_only``, ``browser_id``,
    ``local_state_path`` may be given.

    :param plaintext_only: Reject the whole request if any Chromium row is
        encrypted, rather than guessing a credential for it
    :param browser_id: Registry browser identity for an encrypted Chromium
        database (Linux keyring / macOS Keychain). Unix only.
    :param local_state_path: Path to a Chromium ``Local State`` file, for an
        encrypted Chromium database. Windows only.
    :raises RookieRequestError: More than one credential selector was given
        (``conflicting_credential_selectors``), or a platform-incompatible one
    :raises RookieEngineError: Source inspection failed due to an I/O, SQLite,
        locked, or corrupt-file failure (``source_inspection_failed``), or
        extraction failed after classification
    """
    ...

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
) -> "http.cookiejar.CookieJar":
    """
    Sugar: ``read(...).as_jar()``. Warnings are discarded.

    **Migration trap:** ``include_session`` defaults to ``False``. In
    0.6-beta, ``jar(profile="Default")`` imported that profile's session
    cookies too; it does not in 0.6.0 unless ``include_session=True`` is
    also passed. This fails quietly -- a smaller jar, no error. See
    CHANGELOG.md.
    """
    ...

def profiles(
    browser_id: str,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> ProfileDescriptorList:
    """Alias of ``browser_profiles``."""
    ...

def report(
    browser: str,
    *,
    profile: Optional[str] = None,
    domains: Optional[List[str]] = None,
    select: ReportProfileSelection | None = None,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> ExtractionReport:
    """Bindings name for ``browser_report`` / Rust ``extract_report``."""
    ...

def supported_browsers_dto() -> List[dto.BrowserDescriptor]: ...

def profiles_dto(
    browser_id: str,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> List[dto.ProfileDescriptor]: ...

def report_dto(
    browser: str,
    *,
    profile: Optional[str] = None,
    domains: Optional[List[str]] = None,
    select: ReportProfileSelection | None = None,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> dto.ExtractionReport: ...

def load_report_dto(
    domains: Optional[List[str]] = None,
    *,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
    app_bound: AppBoundPolicy = "injection_only",
) -> dto.ExtractionReport: ...

# Windows
if sys.platform == "win32":
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

    def opera_gx(domains: Optional[List[str]] = None) -> CookieList:
        """Extract Cookies from Opera GX browser."""
        ...

# MacOS
if sys.platform == "darwin":
    def opera_gx(domains: Optional[List[str]] = None) -> CookieList:
        """Extract Cookies from Opera GX browser."""
        ...

    def safari(domains: Optional[List[str]] = None) -> CookieList:
        """
        Extract Cookies from Safari browser

        :param domains: Optional list of domains to extract only from them
        :return: A list of dictionaries of cookies
        """
        ...

# Linux
if sys.platform.startswith("linux"):
    def cachy(domains: Optional[List[str]] = None) -> CookieList:
        """Extract Cookies from Cachy Browser."""
        ...
