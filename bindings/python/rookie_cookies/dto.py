"""Typed dataclasses generated from schema/report-dto.schema.json.

Do not hand-edit -- regenerate with `python3 scripts/generate-python-dto.py`
after `schema/report-dto.schema.json` changes (see `schema/README.md`). See
that script's module docstring for why this exists alongside the
dict-returning API rather than instead of it.

Every open string identifier (browser/engine/cipher-tier/issue-code/...) is
typed as a plain `str`: a value this build has never seen is still
representable, exactly like the Rust source it is generated from. The JSON
Schema and Rust constructors enforce the identifier's lexical shape; these
dataclasses intentionally do not perform runtime validation -- see
`report_core.rs`'s module docs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

__all__ = ["BrowserCapabilitiesDescriptor", "BrowserDescriptor", "Cookie", "CookieSourceDescriptor", "CookieSourceIdentity", "ExtractionIssue", "ExtractionReport", "ExtractionStats", "ProfileDescriptor", "ProfileExtraction", "ProfileIdentity", "ReportStats", "SourceExtraction"]


@dataclass(frozen=True)
class Cookie:
    domain: str
    path: str
    secure: bool
    name: str
    value: str
    http_only: bool
    same_site: int
    expires: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> Cookie:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            domain=data['domain'],
            path=data['path'],
            secure=data['secure'],
            expires=data.get('expires', None),
            name=data['name'],
            value=data['value'],
            http_only=data['http_only'],
            same_site=data['same_site'],
        )


@dataclass(frozen=True)
class BrowserDescriptor:
    """A browser registered for the running OS. Registration is not detection."""
    id: str
    aliases: List[str]
    display_name: str
    engine: str
    capabilities: BrowserCapabilitiesDescriptor

    @classmethod
    def from_dict(cls, data: dict) -> BrowserDescriptor:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            id=data['id'],
            aliases=data['aliases'],
            display_name=data['display_name'],
            engine=data['engine'],
            capabilities=BrowserCapabilitiesDescriptor.from_dict(data['capabilities']),
        )


@dataclass(frozen=True)
class BrowserCapabilitiesDescriptor:
    """What a registered browser claims it can do on this platform.

Declared tiers come from the registry; `available_decryption_tiers` narrows them to the key providers actually compiled and enabled in this build, so it is the set a `decryptable` claim refers to."""
    persistent_formats: List[str]
    session_formats: List[str]
    declared_decryption_tiers: List[str]
    available_decryption_tiers: List[str]

    @classmethod
    def from_dict(cls, data: dict) -> BrowserCapabilitiesDescriptor:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            persistent_formats=data['persistent_formats'],
            session_formats=data['session_formats'],
            declared_decryption_tiers=data['declared_decryption_tiers'],
            available_decryption_tiers=data['available_decryption_tiers'],
        )


@dataclass(frozen=True)
class ProfileDescriptor:
    """One discovered profile and its cookie sources."""
    profile: ProfileIdentity
    is_default: bool
    sources: List[CookieSourceDescriptor]

    @classmethod
    def from_dict(cls, data: dict) -> ProfileDescriptor:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            profile=ProfileIdentity.from_dict(data['profile']),
            is_default=data['is_default'],
            sources=[CookieSourceDescriptor.from_dict(item) for item in data['sources']],
        )


@dataclass(frozen=True)
class ProfileIdentity:
    """Stable identity of one discovered profile.

`profile_id` is the selection key; `path` is a display value that may be lossy on a non-UTF-8 filesystem, which `path_lossy` reports."""
    browser_id: str
    installation_id: str
    profile_id: str
    display_name: str
    path: str
    path_lossy: bool

    @classmethod
    def from_dict(cls, data: dict) -> ProfileIdentity:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            browser_id=data['browser_id'],
            installation_id=data['installation_id'],
            profile_id=data['profile_id'],
            display_name=data['display_name'],
            path=data['path'],
            path_lossy=data['path_lossy'],
        )


@dataclass(frozen=True)
class CookieSourceDescriptor:
    """A cookie source a profile exposes, before any extraction is attempted."""
    role: str
    format: str
    path: str
    path_lossy: bool
    precedence: int

    @classmethod
    def from_dict(cls, data: dict) -> CookieSourceDescriptor:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            role=data['role'],
            format=data['format'],
            path=data['path'],
            path_lossy=data['path_lossy'],
            precedence=data['precedence'],
        )


@dataclass(frozen=True)
class ExtractionReport:
    """A grouped extraction result.

`issues` holds only request-wide, registry, discovery, and installation problems; anything narrower is attached to its profile or source."""
    status: str
    summary: ReportStats
    profiles: List[ProfileExtraction]
    issues: List[ExtractionIssue]
    schema_version: int = 1
    termination: str = 'completed'

    @classmethod
    def from_dict(cls, data: dict) -> ExtractionReport:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            schema_version=data.get('schema_version', 1),
            status=data['status'],
            termination=data.get('termination', 'completed'),
            summary=ReportStats.from_dict(data['summary']),
            profiles=[ProfileExtraction.from_dict(item) for item in data['profiles']],
            issues=[ExtractionIssue.from_dict(item) for item in data['issues']],
        )


@dataclass(frozen=True)
class ReportStats:
    """Request-wide totals, including browsers that were registered but absent."""
    registered_browsers: int
    browsers_detected: int
    browsers_not_detected: int
    installations_discovered: int
    profiles_discovered: int
    sources_succeeded: int
    sources_failed: int
    rows_seen: int
    cookies_emitted: int
    rows_skipped: int
    counters_saturated: bool
    rows_rejected: int = 0
    provider_failures: int = 0

    @classmethod
    def from_dict(cls, data: dict) -> ReportStats:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            registered_browsers=data['registered_browsers'],
            browsers_detected=data['browsers_detected'],
            browsers_not_detected=data['browsers_not_detected'],
            installations_discovered=data['installations_discovered'],
            profiles_discovered=data['profiles_discovered'],
            sources_succeeded=data['sources_succeeded'],
            sources_failed=data['sources_failed'],
            rows_seen=data['rows_seen'],
            cookies_emitted=data['cookies_emitted'],
            rows_skipped=data['rows_skipped'],
            rows_rejected=data.get('rows_rejected', 0),
            provider_failures=data.get('provider_failures', 0),
            counters_saturated=data['counters_saturated'],
        )


@dataclass(frozen=True)
class ProfileExtraction:
    """One profile's sources, totals, and profile-scoped diagnostics."""
    profile: ProfileIdentity
    sources: List[SourceExtraction]
    stats: ExtractionStats
    issues: List[ExtractionIssue]

    @classmethod
    def from_dict(cls, data: dict) -> ProfileExtraction:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            profile=ProfileIdentity.from_dict(data['profile']),
            sources=[SourceExtraction.from_dict(item) for item in data['sources']],
            stats=ExtractionStats.from_dict(data['stats']),
            issues=[ExtractionIssue.from_dict(item) for item in data['issues']],
        )


@dataclass(frozen=True)
class SourceExtraction:
    """One attempted cookie source and the cookies it produced.

Cookies live here rather than on the profile so provenance survives. A profile-wide stream is the concatenation of the successful `selected` sources in role/precedence order."""
    source: CookieSourceIdentity
    status: str
    selected: bool
    acquisition_strategy: str
    cookies: List[Cookie]
    stats: ExtractionStats
    issues: List[ExtractionIssue]

    @classmethod
    def from_dict(cls, data: dict) -> SourceExtraction:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            source=CookieSourceIdentity.from_dict(data['source']),
            status=data['status'],
            selected=data['selected'],
            acquisition_strategy=data['acquisition_strategy'],
            cookies=[Cookie.from_dict(item) for item in data['cookies']],
            stats=ExtractionStats.from_dict(data['stats']),
            issues=[ExtractionIssue.from_dict(item) for item in data['issues']],
        )


@dataclass(frozen=True)
class CookieSourceIdentity:
    """Identity of the source an extraction attempted."""
    role: str
    format: str
    path: str
    path_lossy: bool
    precedence: int

    @classmethod
    def from_dict(cls, data: dict) -> CookieSourceIdentity:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            role=data['role'],
            format=data['format'],
            path=data['path'],
            path_lossy=data['path_lossy'],
            precedence=data['precedence'],
        )


@dataclass(frozen=True)
class ExtractionStats:
    """Row accounting for one source or profile.

`rows_skipped` counts relevant rows rejected after being seen because parsing, decryption, or decoding failed. Every counter is `u32`; a count that exceeded that range is clamped and sets `counters_saturated`."""
    rows_seen: int
    cookies_emitted: int
    rows_skipped: int
    acquisition_attempts: int
    counters_saturated: bool
    rows_rejected: int = 0
    provider_failures: int = 0

    @classmethod
    def from_dict(cls, data: dict) -> ExtractionStats:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            rows_seen=data['rows_seen'],
            cookies_emitted=data['cookies_emitted'],
            rows_skipped=data['rows_skipped'],
            rows_rejected=data.get('rows_rejected', 0),
            provider_failures=data.get('provider_failures', 0),
            acquisition_attempts=data['acquisition_attempts'],
            counters_saturated=data['counters_saturated'],
        )


@dataclass(frozen=True)
class ExtractionIssue:
    """A diagnostic attached to the request, a profile, or a source.

Repeated row-level problems are aggregated by code and stage: `occurrences` counts them all while `samples` keeps a bounded excerpt."""
    code: str
    stage: str
    severity: str
    occurrences: int
    samples: List[str]
    message: str
    cause: str = ''
    provider: Optional[str] = None
    tier: Optional[str] = None
    retryability: str = 'unknown'
    browser_id: Optional[str] = None
    installation_id: Optional[str] = None
    profile_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> ExtractionIssue:
        """Converts one of this package's existing dict-shaped returns (e.g. from `browser_report`) into this typed dataclass."""
        return cls(
            code=data['code'],
            stage=data['stage'],
            severity=data['severity'],
            cause=data.get('cause', ''),
            provider=data.get('provider', None),
            tier=data.get('tier', None),
            retryability=data.get('retryability', 'unknown'),
            occurrences=data['occurrences'],
            samples=data['samples'],
            browser_id=data.get('browser_id', None),
            installation_id=data.get('installation_id', None),
            profile_id=data.get('profile_id', None),
            message=data['message'],
        )
