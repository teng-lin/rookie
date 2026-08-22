"""Build an exact corpus oracle from a hosted browser's persisted metadata.

The installed-browser matrix cannot rely on Playwright's arbitrary-executable
launch contract for every branded fork.  This module therefore reads only the
browser-owned storage metadata needed to bind the declarative seed to an exact
manifest.  Expected values and attributes still come from ``cookie_corpus.json``;
Chromium ciphertext is never treated as an oracle for its decrypted value.
"""

from __future__ import annotations

from email.utils import parsedate_to_datetime
import json
import math
from pathlib import Path
import sqlite3
import struct
import time
from typing import Any, Iterable
from urllib.parse import urlencode

from cookie_manifest import MANIFEST_FILENAME
from run_partition_context_e2e import _firefox_expiry


CORPUS_PATH = Path(__file__).with_name("cookie_corpus.json")
CHROMIUM_EPOCH_OFFSET_US = 11_644_473_600_000_000
SAFARI_EPOCH_OFFSET_SECONDS = 978_307_200.0
TIERS = ("portable_smoke",)


class HostedCorpusError(AssertionError):
    """A browser-owned store disagreed with the declared portable corpus."""


def corpus_engine(engine: str) -> str:
    """Map runner engine names to the corpus vocabulary."""

    return "firefox" if engine == "gecko" else engine


def corpus_seed_url(port: int, engine: str, *, scheme: str = "http") -> str:
    """Return the redirect-chain entry point that applies every corpus phase."""

    if scheme not in {"http", "https"}:
        raise HostedCorpusError(f"unsupported corpus URL scheme {scheme!r}")
    query = urlencode(
        {"engine": corpus_engine(engine), "tiers": ",".join(TIERS), "step": 0}
    )
    return f"{scheme}://127.0.0.1:{port}/corpus/run?{query}"


def expanded_value(operation: dict[str, Any]) -> str:
    """Expand either a literal or repeated declarative cookie value."""

    if "value" in operation:
        return str(operation["value"])
    repeat = operation.get("value_repeat")
    if not isinstance(repeat, dict):
        raise HostedCorpusError("cookie operation must define value or value_repeat")
    return str(repeat["text"]) * int(repeat["count"])


def load_corpus(path: Path = CORPUS_PATH) -> dict[str, Any]:
    """Load the checked-in cookie corpus."""

    return json.loads(path.read_text(encoding="utf-8"))


def applicable_scenarios(
    corpus: dict[str, Any], engine: str, platform: str
) -> list[dict[str, Any]]:
    """Select the portable scenarios declared for one engine and platform."""

    selected = []
    for scenario in corpus["scenarios"]:
        applicability = scenario["applicability"]
        if engine not in applicability["engines"]:
            continue
        if platform not in applicability["platforms"]:
            continue
        if not set(TIERS).intersection(scenario["tiers"]):
            continue
        selected.append(scenario)
    return selected


def _chromium_expiry(raw: object) -> int | None:
    value = int(raw)
    if value <= CHROMIUM_EPOCH_OFFSET_US:
        return None
    return (value - CHROMIUM_EPOCH_OFFSET_US) // 1_000_000


def _optional(row: sqlite3.Row, columns: set[str], name: str) -> object | None:
    return row[name] if name in columns else None


def _chromium_observations(database: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        columns = {
            str(row[1]) for row in connection.execute("pragma table_info(cookies)")
        }
        rows = connection.execute("select * from cookies").fetchall()
    finally:
        connection.close()

    observations = []
    for row in rows:
        top_key = _optional(row, columns, "top_frame_site_key")
        plaintext = str(row["value"]) if "value" in columns and row["value"] else None
        observations.append(
            {
                "domain": str(row["host_key"]),
                "path": str(row["path"]),
                "name": str(row["name"]),
                "observed_value": plaintext,
                "secure": bool(row["is_secure"]),
                "http_only": bool(row["is_httponly"]),
                "same_site": int(row["samesite"]),
                "expires": _chromium_expiry(row["expires_utc"]),
                "context": {
                    "top_frame_site_key": (
                        None if top_key in (None, "") else str(top_key)
                    ),
                    "has_cross_site_ancestor": (
                        bool(_optional(row, columns, "has_cross_site_ancestor"))
                        if "has_cross_site_ancestor" in columns
                        else None
                    ),
                    "source_scheme": (
                        int(_optional(row, columns, "source_scheme"))
                        if "source_scheme" in columns
                        else None
                    ),
                    "source_port": (
                        int(_optional(row, columns, "source_port"))
                        if "source_port" in columns
                        else None
                    ),
                    "is_persistent": (
                        bool(_optional(row, columns, "is_persistent"))
                        if "is_persistent" in columns
                        else None
                    ),
                    "origin_attributes": None,
                    "user_context_id": None,
                    "partition_key": None,
                    "private_browsing_id": None,
                },
            }
        )
    return observations


def _firefox_observations(database: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        columns = {
            str(row[1]) for row in connection.execute("pragma table_info(moz_cookies)")
        }
        schema_version = int(connection.execute("pragma user_version").fetchone()[0])
        rows = connection.execute("select * from moz_cookies").fetchall()
    finally:
        connection.close()

    observations = []
    for row in rows:
        origin_attributes = str(_optional(row, columns, "originAttributes") or "")
        raw_same_site = int(row["sameSite"])
        observations.append(
            {
                "domain": str(row["host"]),
                "path": str(row["path"]),
                "name": str(row["name"]),
                "observed_value": str(row["value"]),
                "secure": bool(row["isSecure"]),
                "http_only": bool(row["isHttpOnly"]),
                # Current Gecko uses 256 as the raw persisted sentinel for an
                # unspecified SameSite attribute. The public Cookie contract
                # normalizes every unknown/raw sentinel to -1.
                "same_site": raw_same_site if raw_same_site in {0, 1, 2} else -1,
                "expires": _firefox_expiry(row["expiry"], schema_version),
                "context": {
                    "top_frame_site_key": None,
                    "has_cross_site_ancestor": None,
                    "source_scheme": None,
                    "source_port": None,
                    "is_persistent": None,
                    "origin_attributes": origin_attributes,
                    "user_context_id": None,
                    "partition_key": None,
                    "private_browsing_id": None,
                },
            }
        )
    return observations


def _slice(data: bytes, offset: int, length: int, label: str) -> bytes:
    end = offset + length
    if offset < 0 or length < 0 or end > len(data):
        raise HostedCorpusError(f"Safari {label} extends outside its binary image")
    return data[offset:end]


def _c_string(data: bytes, start: int, end: int, label: str) -> str:
    value = _slice(data, start, end - start, label).split(b"\0", 1)[0]
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HostedCorpusError(f"Safari {label} is not UTF-8") from error


def _safari_record(record: bytes) -> dict[str, Any]:
    if len(record) < 0x30:
        raise HostedCorpusError("Safari cookie record is shorter than its header")
    flags = struct.unpack_from("<I", record, 0x08)[0]
    domain_offset, name_offset, path_offset, value_offset = struct.unpack_from(
        "<IIII", record, 0x10
    )
    if not (0x30 <= domain_offset <= name_offset <= path_offset <= value_offset):
        raise HostedCorpusError("Safari cookie string offsets are not ordered")
    raw_expiry = struct.unpack_from("<d", record, 0x28)[0]
    expires = (
        int(raw_expiry + SAFARI_EPOCH_OFFSET_SECONDS)
        if raw_expiry != 0.0 and math.isfinite(raw_expiry)
        else None
    )
    return {
        "domain": _c_string(record, domain_offset, name_offset, "domain"),
        "name": _c_string(record, name_offset, path_offset, "name"),
        "path": _c_string(record, path_offset, value_offset, "path"),
        "observed_value": _c_string(record, value_offset, len(record), "value"),
        "secure": bool(flags & 0x01),
        "http_only": bool(flags & 0x04),
        "same_site": -1,
        "expires": expires,
        "context": {
            "top_frame_site_key": None,
            "has_cross_site_ancestor": None,
            "source_scheme": None,
            "source_port": None,
            "is_persistent": None,
            "origin_attributes": None,
            "user_context_id": None,
            "partition_key": None,
            "private_browsing_id": None,
        },
    }


def _safari_observations(database: Path) -> list[dict[str, Any]]:
    data = database.read_bytes()
    if data[:4] != b"cook":
        raise HostedCorpusError("Safari cookie store has an invalid signature")
    page_count = struct.unpack(">I", _slice(data, 4, 4, "page count"))[0]
    lengths_offset = 8
    page_lengths = [
        struct.unpack(">I", _slice(data, lengths_offset + index * 4, 4, "page length"))[
            0
        ]
        for index in range(page_count)
    ]
    page_offset = lengths_offset + page_count * 4
    observations = []
    for page_index, page_length in enumerate(page_lengths):
        page = _slice(data, page_offset, page_length, f"page {page_index}")
        page_offset += page_length
        if page[:4] != b"\x00\x00\x01\x00":
            raise HostedCorpusError(f"Safari page {page_index} has an invalid header")
        count = struct.unpack("<I", _slice(page, 4, 4, "record count"))[0]
        offsets = [
            struct.unpack("<I", _slice(page, 8 + index * 4, 4, "record offset"))[0]
            for index in range(count)
        ]
        for record_index, record_offset in enumerate(offsets):
            record_length = struct.unpack(
                "<I", _slice(page, record_offset, 4, "record length")
            )[0]
            record = _slice(
                page,
                record_offset,
                record_length,
                f"page {page_index} record {record_index}",
            )
            observations.append(_safari_record(record))
    return observations


def read_observations(engine: str, database: Path) -> list[dict[str, Any]]:
    """Read browser-owned metadata without using a rookie-cookies decoder."""

    if engine == "chromium":
        return _chromium_observations(database)
    if engine == "firefox":
        return _firefox_observations(database)
    if engine == "safari":
        return _safari_observations(database)
    raise HostedCorpusError(f"unsupported hosted corpus engine {engine!r}")


def _normalized_domain(domain: str) -> str:
    return domain.removeprefix(".").lower()


def _matches(
    observation: dict[str, Any], scenario: dict[str, Any], corpus: dict[str, Any]
) -> bool:
    operation = scenario["operations"][-1]
    hostname = corpus["origins"][scenario["origin"]]["hostname"]
    domain = _normalized_domain(str(observation["domain"]))
    expected_domain = _normalized_domain(str(operation.get("domain", hostname)))
    return (
        domain == expected_domain
        and observation["name"] == operation["name"]
        and observation["path"] == operation.get("path", "/")
    )


def _expected_expiry_window(
    scenario: dict[str, Any], operation: dict[str, Any], browser: str
) -> tuple[int, int] | None:
    expected = scenario["expected"]
    window = expected.get("expiry_seconds_from_now_by_browser", {}).get(browser)
    window = window or expected.get("expiry_seconds_from_now")
    if window:
        return int(window["min"]), int(window["max"])
    max_age = operation.get("max_age")
    if isinstance(max_age, int) and max_age > 0:
        tolerance = max(300, min(900, max_age // 10))
        return max(1, max_age - tolerance), max_age + tolerance
    if "expires" in operation:
        absolute = int(parsedate_to_datetime(operation["expires"]).timestamp())
        now = int(time.time())
        return absolute - now - 5, absolute - now + 5
    return None


def _validate_observation(
    observation: dict[str, Any],
    scenario: dict[str, Any],
    engine: str,
    browser: str,
) -> dict[str, Any]:
    operation = scenario["operations"][-1]
    expected_value = expanded_value(operation)
    expected_same_site = int(scenario["expected"]["same_site"][engine])
    mismatches = []
    observed_value = observation.get("observed_value")
    if observed_value is not None and observed_value != expected_value:
        mismatches.append(f"value={observed_value!r}")
    for field, expected in (
        ("path", operation.get("path", "/")),
        ("secure", bool(operation.get("secure"))),
        ("http_only", bool(operation.get("http_only"))),
        ("same_site", expected_same_site),
    ):
        if observation[field] != expected:
            mismatches.append(f"{field}={observation[field]!r}, expected={expected!r}")

    expires = observation["expires"]
    expiry_window = _expected_expiry_window(scenario, operation, browser)
    if expiry_window is None:
        if expires is not None:
            mismatches.append(f"expires={expires!r}, expected session")
    elif not isinstance(expires, int):
        mismatches.append("expires=session, expected persistent")
    else:
        delta = expires - int(time.time())
        if not expiry_window[0] <= delta <= expiry_window[1]:
            mismatches.append(
                f"expiry_seconds_from_now={delta}, expected {expiry_window[0]}..{expiry_window[1]}"
            )
    if mismatches:
        raise HostedCorpusError(
            f"persisted scenario {scenario['id']!r} disagreed: {', '.join(mismatches)}"
        )

    return {
        "domain": str(observation["domain"]),
        "path": str(observation["path"]),
        "secure": bool(observation["secure"]),
        "expires": expires,
        "name": str(operation["name"]),
        "value": expected_value,
        "http_only": bool(observation["http_only"]),
        "same_site": expected_same_site,
    }


def build_manifest(
    *,
    engine: str,
    browser: str,
    platform: str,
    observations: Iterable[dict[str, Any]],
    corpus: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate and convert one complete browser-owned corpus to a manifest."""

    corpus = corpus or load_corpus()
    engine = corpus_engine(engine)
    scenarios = applicable_scenarios(corpus, engine, platform)
    origin_domains = {
        origin["hostname"].lower() for origin in corpus["origins"].values()
    }
    all_observed = list(observations)
    observed = [
        item
        for item in all_observed
        if _normalized_domain(str(item["domain"])) in origin_domains
    ]
    unmatched = set(range(len(observed)))
    filtered = []
    unfiltered = []
    detailed = []
    excluded = []
    scenario_observations = []

    for scenario in scenarios:
        matches = [
            (index, item)
            for index, item in enumerate(observed)
            if _matches(item, scenario, corpus)
        ]
        if not scenario["expected"]["stored"]:
            if matches:
                raise HostedCorpusError(
                    f"deleted/rejected scenario {scenario['id']!r} remained in the store"
                )
            excluded.append(
                {"scenario_id": scenario["id"], "reason": "expected_not_stored"}
            )
            scenario_observations.append(
                {"scenario_id": scenario["id"], "stored": False}
            )
            continue
        if len(matches) != 1:
            raise HostedCorpusError(
                f"scenario {scenario['id']!r} expected exactly one persisted cookie, "
                f"observed {len(matches)}"
            )
        index, observation = matches[0]
        unmatched.discard(index)
        flat = _validate_observation(observation, scenario, engine, browser)
        unfiltered.append(flat)
        origin = corpus["origins"][scenario["origin"]]
        if origin["included_by_domain_filter"]:
            filtered.append(flat)
        detailed.append({"cookie": flat, "context": observation["context"]})
        scenario_observations.append(
            {
                "scenario_id": scenario["id"],
                "stored": True,
                "domain": flat["domain"],
                "expires": flat["expires"],
            }
        )

    if unmatched:
        excess = [
            f"{observed[index]['domain']}{observed[index]['path']}:"
            f"{observed[index]['name']}"
            for index in sorted(unmatched)
        ]
        raise HostedCorpusError(
            f"fresh hosted profile contained unexpected target-domain cookies: {excess}"
        )
    if len(unfiltered) < 10:
        raise HostedCorpusError(
            f"portable corpus unexpectedly collapsed to {len(unfiltered)} stored rows"
        )

    return {
        "schema_version": 1,
        "corpus_schema_version": corpus["schema_version"],
        "engine": engine,
        "platform": platform,
        "tiers": list(TIERS),
        "browser": {"id": browser, "source": "hosted-persisted-metadata"},
        "domain_filter": corpus["origins"]["primary"]["hostname"],
        "verification_scope": {
            "cookie_domains": sorted(origin_domains),
            "browser_owned_external_rows_observed": len(all_observed) - len(observed),
        },
        "identities": corpus["identities"],
        "expected": {
            "filtered_flat": filtered,
            "unfiltered_flat": unfiltered,
            "detailed": detailed,
        },
        "excluded": excluded,
        "observations": scenario_observations,
    }


def write_hosted_manifest(
    *,
    engine: str,
    browser: str,
    platform: str,
    profile: Path,
    database: Path,
) -> Path:
    """Write the exact manifest next to one isolated hosted profile."""

    manifest = build_manifest(
        engine=engine,
        browser=browser,
        platform=platform,
        observations=read_observations(corpus_engine(engine), database),
    )
    path = profile / MANIFEST_FILENAME
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"hosted exact corpus: {len(manifest['expected']['filtered_flat'])} filtered / "
        f"{len(manifest['expected']['unfiltered_flat'])} total cookies; manifest: {path}",
        flush=True,
    )
    return path
