#!/usr/bin/env python3
"""Run browser-produced CHIPS/dFPI isolation checks on an isolated CI host."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlparse
from urllib.request import HTTPSHandler, build_opener

from assert_partitioned_context import schemeful_site
from browser_coverage_contract import emit_representative_depth
from cookie_manifest import paths_refer_to_same_file
from run_active_writer_e2e import (
    ActiveWriterError,
    ROOT,
    pick_port,
    run_checked,
    venv_python,
)
from run_exact_corpus_e2e import (
    REGISTRY_PATH,
    configure_isolated_keychain,
    isolated_environment,
    platform_id,
    resolve_registry_root,
)


MARKER = {
    "schema_version": 1,
    "kind": "rookie-cookie-fixture-source",
    "source_kind": "disposable_e2e_profile",
}

# Every host the lane resolves to the disposable HTTPS origin. nested shares a
# registrable site with top, which is the only reason an A -> B -> A ancestor
# chain is expressible without a second certificate or a public-suffix rule.
TEST_HOSTS = (
    "top.rookie-a.test",
    "other.rookie-c.test",
    "third.rookie-b.test",
    "nested.rookie-a.test",
)
INVENTORY_PATH = Path(__file__).with_name("partition_context_inventory.json")
# Firefox omits a default-valued origin attribute, so a name outside this set
# (or a known name whose value will not parse) is a row this build cannot
# decompose, and it demands the raw `origin_attributes` selector.
KNOWN_FIREFOX_ATTRIBUTES = frozenset(
    {
        "userContextId",
        "privateBrowsingId",
        "partitionKey",
        "firstPartyDomain",
        "geckoViewSessionContextId",
    }
)
# ADR 0006 Decision 5: appended, never reordered.
SELECTOR_TOKEN_ORDER = (
    "top_level_site",
    "user_context_id",
    "private_browsing_id",
    "first_party_domain",
    "gecko_view_session_context_id",
    "origin_attributes",
)
DEFAULT_PORTS = {"https": 443, "http": 80}


def row_inventory(engine: str) -> dict[str, Any]:
    """Return the one expected-row table every partition-context actor reads."""

    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    if inventory.get("schema_version") != 1:
        raise ActiveWriterError(
            f"unsupported partition inventory schema {inventory.get('schema_version')!r}"
        )
    try:
        entry = inventory["engines"][engine]
    except KeyError as error:
        raise ActiveWriterError(
            f"partition_context_inventory.json has no {engine} entry"
        ) from error
    if sum(entry["raw_rows_by_name"].values()) != entry["raw_row_total"]:
        raise ActiveWriterError(
            f"{engine} inventory total disagrees with its per-name counts: {entry!r}"
        )
    return entry


def require_remote_sandbox(path: Path) -> Path:
    if os.environ.get("CI", "").lower() != "true":
        raise ActiveWriterError(
            "partition context capture is restricted to isolated CI"
        )
    runner_temp_raw = os.environ.get("RUNNER_TEMP")
    if not runner_temp_raw:
        raise ActiveWriterError(
            "RUNNER_TEMP must identify the isolated CI scratch root"
        )
    runner_temp = Path(runner_temp_raw).resolve(strict=True)
    sandbox = path.resolve()
    try:
        sandbox.relative_to(runner_temp)
    except ValueError as error:
        raise ActiveWriterError(f"sandbox {sandbox} is outside RUNNER_TEMP") from error
    sandbox.mkdir(parents=True, exist_ok=True)
    return sandbox


def playwright_executable(engine: str) -> str:
    browser_type = "chromium" if engine == "chromium" else "firefox"
    result = subprocess.run(
        [
            "node",
            "-e",
            f"process.stdout.write(require('playwright').{browser_type}.executablePath())",
        ],
        cwd=str(ROOT / "tests/e2e"),
        check=True,
        capture_output=True,
        text=True,
    )
    executable = Path(result.stdout).resolve(strict=True)
    return str(executable)


def discovery_layout(engine: str, sandbox: Path) -> tuple[Path, dict[str, str]]:
    environment = os.environ.copy()
    environment.update(isolated_environment(sandbox))
    configure_isolated_keychain(environment)
    if not environment.get("ROOKIE_E2E_BROWSER_PATH"):
        environment["ROOKIE_E2E_BROWSER_PATH"] = playwright_executable(engine)
    browser_id = "chromium" if engine == "chromium" else "firefox"
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    entries = [
        entry
        for entry in registry["platforms"][platform_id()]
        if entry["canonical_id"] == browser_id
    ]
    if len(entries) != 1:
        raise ActiveWriterError(
            f"expected one registry entry for {platform_id()}/{browser_id}, got {len(entries)}"
        )
    root_spec = min(entries[0]["roots"], key=lambda candidate: candidate["priority"])
    root = resolve_registry_root(root_spec["template"], environment)
    if engine == "chromium":
        profile = root
    else:
        profile = root / "Profiles/rookie-context"
        profile.mkdir(parents=True, exist_ok=True)
        (root / "profiles.ini").write_text(
            "[Profile0]\nName=rookie-context\nIsRelative=1\n"
            "Path=Profiles/rookie-context\nDefault=1\n",
            encoding="utf-8",
        )
    profile.mkdir(parents=True, exist_ok=True)
    (profile / ".rookie-cookie-fixture-source.json").write_text(
        json.dumps(MARKER, sort_keys=True) + "\n", encoding="utf-8"
    )
    return profile, environment


def generate_certificate(sandbox: Path) -> tuple[Path, Path]:
    certificate = sandbox / "context-cert.pem"
    private_key = sandbox / "context-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=rookie-context-e2e",
            "-addext",
            "subjectAltName=" + ",".join(f"DNS:{host}" for host in TEST_HOSTS),
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    return certificate, private_key


def wait_for_https(port: int, process: subprocess.Popen[Any], timeout: float) -> None:
    import time

    deadline = time.monotonic() + timeout
    opener = build_opener(HTTPSHandler(context=ssl._create_unverified_context()))
    endpoint = f"https://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ActiveWriterError(f"context server exited {process.returncode}")
        try:
            with opener.open(endpoint, timeout=0.5) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise ActiveWriterError(f"context HTTPS server did not bind {endpoint}")


def database_for(engine: str, profile: Path) -> Path:
    if engine == "firefox":
        return (profile / "cookies.sqlite").resolve(strict=True)
    for relative in ("Default/Network/Cookies", "Default/Cookies"):
        candidate = profile / relative
        if candidate.is_file():
            return candidate.resolve()
    raise ActiveWriterError(f"no Chromium cookie DB below {profile}")


def discovered_profile_id(engine: str, browser_id: str, database: Path) -> str:
    import rookie_cookies

    matches = [
        profile
        for profile in rookie_cookies.browser_profiles(browser_id)
        if any(
            paths_refer_to_same_file(source["path"], database)
            for source in profile["sources"]
        )
    ]
    if len(matches) != 1:
        raise ActiveWriterError(
            f"discovery found {len(matches)} {browser_id} profiles for {database}: {matches!r}"
        )
    identity = matches[0]["profile"]
    if identity["browser_id"] != browser_id:
        raise ActiveWriterError(f"wrong discovered browser identity: {identity!r}")
    return str(identity["profile_id"])


def schema_metadata(database: Path, engine: str) -> dict[str, Any]:
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        metadata: dict[str, Any] = {
            "journal_mode": connection.execute("pragma journal_mode").fetchone()[0],
            "schema_version": connection.execute("pragma schema_version").fetchone()[0],
        }
        if engine == "chromium":
            row = connection.execute(
                "select value from meta where key='version'"
            ).fetchone()
            metadata["browser_schema_version"] = row[0] if row else None
        else:
            metadata["browser_schema_version"] = connection.execute(
                "pragma user_version"
            ).fetchone()[0]
        return metadata
    finally:
        connection.close()


def _chromium_expiry(raw: object) -> int | None:
    value = int(raw)
    offset = 11_644_473_600_000_000
    return (value - offset) // 1_000_000 if value > offset else None


def _firefox_expiry(raw: object, schema_version: int) -> int | None:
    value = int(raw)
    if value <= 0:
        return None
    return value // 1000 if schema_version >= 16 else value


def _unsigned(attributes: dict[str, str], name: str) -> int | None:
    value = attributes.get(name)
    return int(value) if value is not None and value.isdigit() else None


def _explicit_port(url: str) -> int | None:
    """Return a URL's port, or None when it is the scheme's default.

    ADR 0006 derives the Firefox partition port from the top-level URL rather
    than from a selector of its own, and a scheme-default port is not written
    into either engine's stored key, so "absent" and "default" have to compare
    equal here too.
    """

    parsed = urlparse(url)
    port = parsed.port
    if port is None or port == DEFAULT_PORTS.get(parsed.scheme):
        return None
    return port


def _host_within(request_host: str, site_host: str) -> bool:
    """Site membership: equal hosts, or a subdomain of the top-level site.

    No public-suffix list, matching ADR 0006 Decision 4. This lane only ever
    passes controlled `.test` hosts, so the registrable-site question the
    decision documents as the caller's job cannot arise.
    """

    return request_host == site_host or request_host.endswith(f".{site_host}")


def _resolve_chain(send_context: dict[str, Any]) -> tuple[bool, str]:
    """Return `(sites_match, resolved_ancestor_chain)` for a send context.

    The resolved chain is `cross_site` whenever the request and top-level
    sites differ, regardless of any explicit selector; otherwise it is the
    explicit selector, defaulting to `same_site`.
    """

    request = urlparse(send_context["url"])
    site = urlparse(send_context["top_level_site"])
    sites_match = request.scheme == site.scheme and _host_within(
        request.hostname or "", site.hostname or ""
    )
    if not sites_match:
        return False, "cross_site"
    return True, send_context.get("ancestor_chain", "same_site")


def _parse_firefox_partition_tuple(
    key: str,
) -> tuple[str, str, int | None, bool] | None:
    """Parse `(scheme,host[,port][,f])`; None for anything else."""

    if not key.startswith("(") or not key.endswith(")"):
        return None
    fields = key[1:-1].split(",")
    if not 2 <= len(fields) <= 4 or not fields[0] or not fields[1]:
        return None
    scheme, host = fields[0], fields[1]
    rest = fields[2:]
    foreign = bool(rest) and rest[-1] == "f"
    if foreign:
        rest = rest[:-1]
    port: int | None = None
    if rest:
        if len(rest) != 1 or not rest[0].isdigit():
            return None
        port = int(rest[0])
    return scheme, host, port, foreign


def _chromium_isolation_reason(
    fields: dict[str, Any], send_context: dict[str, Any], resolved: str
) -> str | None:
    top_key = fields["top_frame_site_key"]
    if top_key in (None, ""):
        return None
    bit = fields["has_cross_site_ancestor"]
    if bit is None:
        return "ancestor_chain_unknown"
    key = urlparse(str(top_key))
    site = urlparse(send_context["top_level_site"])
    if (key.scheme, key.hostname) != (site.scheme, site.hostname):
        return "partition"
    if _explicit_port(str(top_key)) != _explicit_port(send_context["top_level_site"]):
        return "partition"
    if bool(bit) != (resolved == "cross_site"):
        return "partition"
    return None


def _firefox_isolation_reason(
    fields: dict[str, Any],
    send_context: dict[str, Any],
    *,
    sites_match: bool,
    resolved: str,
    same_site_context: bool,
) -> str | None:
    key = fields["partition_key"]
    if key in (None, ""):
        return None
    parsed = _parse_firefox_partition_tuple(str(key))
    if parsed is None:
        # An unreadable key makes the row opaque, and `RequestIsolation::verdict`
        # answers that before any field-by-field gate: there is nothing to
        # compare, so the first-party guard below never gets a say. Ordering
        # this the other way would attribute the row to `partition` and
        # disagree with the core over a row both agree to withhold.
        return "unparsable_partition_key"
    if same_site_context:
        # A partition is by construction not the unpartitioned default
        # context, so a first-party request never reaches into one.
        return "partition"
    scheme, host, port, foreign = parsed
    site = urlparse(send_context["top_level_site"])
    if (scheme, host) != (site.scheme, site.hostname):
        return "partition"
    if port != _explicit_port(send_context["top_level_site"]):
        return "partition"
    if foreign != (sites_match and resolved == "cross_site"):
        return "partition"
    return None


def _omission_reason(
    record: dict[str, Any], send_context: dict[str, Any], engine: str
) -> str | None:
    """The first reason a raw row is not sent, or None when it is selected.

    This is the independent half of the lane: it reads the browser's own
    SQLite rows and applies ADR 0006's rules directly, so the expected send
    set never borrows the library's answer to the question being asked.
    Attribution follows the ADR's evaluation order -- expiry, then the
    domain/path/Secure filter, then isolation, then SameSite -- and every row
    in this corpus is unexpired, so the expiry stage never fires.
    """

    cookie = record["cookie"]
    fields = record["context"]
    if send_context.get("origin_attributes") is not None:
        # The raw suffix selector governs opaque rows, which this oracle does
        # not model. No lane context supplies one; a future one that does must
        # teach the oracle first rather than get a quietly wrong expectation.
        raise ActiveWriterError(
            "the send-view oracle does not model the raw origin_attributes selector"
        )
    request = urlparse(send_context["url"])
    if cookie["domain"].removeprefix(".") != request.hostname:
        return "not_applicable"
    if not (request.path or "/").startswith(cookie["path"]):
        return "not_applicable"
    if cookie["secure"] and request.scheme != "https":
        return "not_applicable"
    sites_match, resolved = _resolve_chain(send_context)
    same_site_context = sites_match and resolved == "same_site"
    if engine == "chromium":
        isolation = _chromium_isolation_reason(fields, send_context, resolved)
    else:
        isolation = _firefox_isolation_reason(
            fields,
            send_context,
            sites_match=sites_match,
            resolved=resolved,
            same_site_context=same_site_context,
        )
    if isolation is not None:
        return isolation
    # Every context this lane builds is a `subresource` request, so the
    # cross-site top-level-navigation exemption Lax otherwise has cannot apply.
    if cookie["same_site"] >= 1 and not same_site_context:
        return "same_site"
    return None


def send_view_contexts(
    *, top_origin: str, other_top_origin: str, third_origin: str, nested_origin: str
) -> list[tuple[str, dict[str, Any]]]:
    """The send contexts every public surface is held to, in manifest order.

    `nested_*` are the three readings of one A-site iframe: derived (which must
    agree with the explicit same-site selector) and the explicit cross-site
    selector that names the A -> B -> A embed the derived rule cannot see.
    `top_*` pair a first-party request against the same request declared
    cross-site, which is what makes the `SameSite=Lax` omission observable.
    """

    top_site = schemeful_site(top_origin)
    other_site = schemeful_site(other_top_origin)
    base = {"resource": "subresource", "method": "safe"}
    third = f"{third_origin}/echo"
    nested = f"{nested_origin}/set-ancestor"
    top = f"{top_origin}/chain-top"
    return [
        ("matching", {"url": third, "top_level_site": top_site, **base}),
        (
            "other_top_level_site",
            {"url": third, "top_level_site": other_site, **base},
        ),
        ("nested_derived", {"url": nested, "top_level_site": top_site, **base}),
        (
            "nested_same_site",
            {
                "url": nested,
                "top_level_site": top_site,
                "ancestor_chain": "same_site",
                **base,
            },
        ),
        (
            "nested_cross_site",
            {
                "url": nested,
                "top_level_site": top_site,
                "ancestor_chain": "cross_site",
                **base,
            },
        ),
        ("top_first_party", {"url": top, "top_level_site": top_site, **base}),
        (
            "top_cross_site",
            {
                "url": top,
                "top_level_site": top_site,
                "ancestor_chain": "cross_site",
                **base,
            },
        ),
    ]


def _record_sort_key(record: dict[str, Any]) -> tuple[str, ...]:
    cookie = record["cookie"]
    return (
        cookie["domain"],
        cookie["path"],
        cookie["name"],
        json.dumps(record["context"], sort_keys=True),
    )


def _expected_send_views(
    detailed: list[dict[str, Any]],
    contexts: list[tuple[str, dict[str, Any]]],
    engine: str,
) -> list[dict[str, Any]]:
    views: list[dict[str, Any]] = []
    for name, send_context in contexts:
        selected: list[dict[str, Any]] = []
        omitted: dict[str, int] = {}
        for record in detailed:
            reason = _omission_reason(record, send_context, engine)
            if reason is None:
                selected.append(record)
            else:
                omitted[reason] = omitted.get(reason, 0) + 1
        views.append(
            {
                "name": name,
                "context": send_context,
                "expected": sorted(selected, key=_record_sort_key),
                "header_tokens": sorted(
                    f"{record['cookie']['name']}={record['cookie']['value']}"
                    for record in selected
                ),
                # A lower bound, not an equality: the omission counters see the
                # whole snapshot, and a browser is free to leave a cookie of its
                # own in a disposable profile. Every rookie_ row is accounted
                # for here, which is what the claim is about.
                "expected_omitted_min": dict(sorted(omitted.items())),
            }
        )
    return views


def _demanded_selectors(detailed: list[dict[str, Any]], engine: str) -> list[str]:
    """The tokens an incomplete send context must name, in ADR 0006 order."""

    demanded: set[str] = set()
    for record in detailed:
        fields = record["context"]
        if fields["top_frame_site_key"] not in (None, "") or fields[
            "partition_key"
        ] not in (None, ""):
            demanded.add("top_level_site")
        if (fields["user_context_id"] or 0) > 0:
            demanded.add("user_context_id")
        if (fields["private_browsing_id"] or 0) > 0:
            demanded.add("private_browsing_id")
        raw = fields["origin_attributes"]
        if engine != "chromium" and raw:
            parsed = dict(parse_qsl(str(raw).removeprefix("^")))
            if parsed.get("firstPartyDomain"):
                demanded.add("first_party_domain")
            if parsed.get("geckoViewSessionContextId"):
                demanded.add("gecko_view_session_context_id")
            if set(parsed) - KNOWN_FIREFOX_ATTRIBUTES:
                demanded.add("origin_attributes")
    return [token for token in SELECTOR_TOKEN_ORDER if token in demanded]


def assert_ancestor_identities(
    detailed: list[dict[str, Any]], engine: str, version: str
) -> None:
    """Require both ancestor chains to have survived as distinct stored rows.

    This never skips. A browser that collapsed A -> A and A -> B -> A into one
    row, or that recorded no foreign-ancestor marker, is a finding about that
    browser version, and the version is named so the finding is actionable.
    """

    rows = [
        record for record in detailed if record["cookie"]["name"] == "rookie_ancestor"
    ]
    values = sorted(record["cookie"]["value"] for record in rows)
    if values != ["ancestor-cross_site", "ancestor-same_site"]:
        raise ActiveWriterError(
            f"{engine} {version} did not keep both ancestor chains apart; "
            f"rookie_ancestor rows were {values}"
        )
    if engine == "chromium":
        bits = sorted(
            bool(record["context"]["has_cross_site_ancestor"]) for record in rows
        )
        if bits != [False, True]:
            raise ActiveWriterError(
                f"Chromium {version} stored has_cross_site_ancestor {bits}, expected "
                "0 for the same-site chain and 1 for the A -> B -> A chain"
            )
        return
    cross = next(
        record for record in rows if record["cookie"]["value"] == "ancestor-cross_site"
    )
    key = str(cross["context"]["partition_key"] or "")
    parsed = _parse_firefox_partition_tuple(key)
    if parsed is None or not parsed[3]:
        raise ActiveWriterError(
            f"Firefox {version} wrote no foreign-by-ancestor `,f` partitionKey for "
            f"the A -> B -> A row; it stored {key!r} (originAttributes "
            f"{cross['context']['origin_attributes']!r}). The `,f` tuple field is "
            "what makes an A -> B -> A embed a distinct Firefox partition, so this "
            "lane fails rather than skipping."
        )
    if (parsed[0], parsed[1]) != ("https", "rookie-a.test"):
        raise ActiveWriterError(
            f"Firefox {version} partitioned the A -> B -> A row under {key!r}, "
            "expected the A site"
        )


def write_raw_context_manifest(
    database: Path,
    engine: str,
    output: Path,
    *,
    origins: dict[str, str],
    browser_version: str | None = None,
) -> None:
    """Build an exact oracle directly from the browser's raw SQLite context."""

    table = "cookies" if engine == "chromium" else "moz_cookies"
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        schema_version = int(connection.execute("pragma user_version").fetchone()[0])
        columns = {
            str(row[1]) for row in connection.execute(f"pragma table_info({table})")
        }
        rows = connection.execute(
            f"select * from {table} where name like 'rookie_%'"
        ).fetchall()
    finally:
        connection.close()

    inventory = row_inventory(engine)
    version = browser_version or "an unrecorded version"
    if len(rows) != inventory["raw_row_total"]:
        observed: dict[str, int] = {}
        for row in rows:
            observed[str(row["name"])] = observed.get(str(row["name"]), 0) + 1
        raise ActiveWriterError(
            f"raw {engine} context store ({version}) contained {len(rows)} rookie "
            f"rows {observed}; partition_context_inventory.json expects "
            f"{inventory['raw_row_total']} {inventory['raw_rows_by_name']}"
        )

    detailed: list[dict[str, Any]] = []
    for row in rows:
        if engine == "chromium":
            top_key_raw = row["top_frame_site_key"]
            top_key = str(top_key_raw) if top_key_raw not in (None, "") else None
            name = str(row["name"])
            host = str(row["host_key"])
            ancestor_bit = (
                row["has_cross_site_ancestor"]
                if "has_cross_site_ancestor" in columns
                else None
            )
            if name == "rookie_top":
                labels = {
                    "top.rookie-a.test": "a",
                    "other.rookie-c.test": "c",
                }
                if host not in labels or top_key is not None:
                    raise ActiveWriterError(
                        f"unexpected Chromium top-cookie identity: {host!r}, {top_key!r}"
                    )
                label = labels[host]
                value = f"top-{label}"
            elif name == "rookie_ancestor":
                # The value is encrypted in the store, so it is reconstructed
                # from the stored identity -- which makes reconstructing it an
                # assertion that the ancestor bit is the thing separating the
                # two otherwise identical rows.
                if host != "nested.rookie-a.test" or top_key is None:
                    raise ActiveWriterError(
                        f"unexpected Chromium ancestor identity: {host!r}, {top_key!r}"
                    )
                if urlparse(top_key).hostname != "rookie-a.test":
                    raise ActiveWriterError(
                        f"ancestor rows must be partitioned under the A site, "
                        f"got {top_key!r}"
                    )
                if ancestor_bit is None or int(ancestor_bit) not in (0, 1):
                    raise ActiveWriterError(
                        f"Chromium {version} stored no usable has_cross_site_ancestor "
                        f"for {top_key!r}: {ancestor_bit!r}"
                    )
                value = (
                    "ancestor-cross_site"
                    if int(ancestor_bit) == 1
                    else "ancestor-same_site"
                )
            elif name != "rookie_chips" or host != "third.rookie-b.test":
                raise ActiveWriterError(
                    f"unexpected Chromium context identity: {host!r}/{name!r}"
                )
            elif top_key is None:
                value = "unpartitioned"
            else:
                top_host = urlparse(top_key).hostname
                labels = {"rookie-a.test": "a", "rookie-c.test": "c"}
                if top_host not in labels:
                    raise ActiveWriterError(
                        f"unexpected Chromium partition key {top_key!r}"
                    )
                label = labels[top_host]
                value = f"partition-{label}"
            flat = {
                "domain": host,
                "path": str(row["path"]),
                "secure": bool(row["is_secure"]),
                "expires": _chromium_expiry(row["expires_utc"]),
                "name": name,
                "value": value,
                "http_only": bool(row["is_httponly"]),
                "same_site": int(row["samesite"]),
            }
            context = {
                "top_frame_site_key": top_key,
                "has_cross_site_ancestor": (
                    bool(ancestor_bit) if ancestor_bit is not None else None
                ),
                "source_scheme": (
                    int(row["source_scheme"])
                    if "source_scheme" in columns and row["source_scheme"] is not None
                    else None
                ),
                "source_port": (
                    int(row["source_port"])
                    if "source_port" in columns and row["source_port"] is not None
                    else None
                ),
                "is_persistent": (
                    bool(row["is_persistent"]) if "is_persistent" in columns else None
                ),
                "origin_attributes": None,
                "user_context_id": None,
                "partition_key": None,
                "private_browsing_id": None,
            }
        else:
            origin_attributes = str(row["originAttributes"] or "")
            parsed = dict(parse_qsl(origin_attributes.removeprefix("^")))
            name = str(row["name"])
            host = str(row["host"])
            value = str(row["value"])
            valid_values = {
                "rookie_top": {"top-a", "top-c"},
                "rookie_chips": {"unpartitioned", "partition-a", "partition-c"},
                "rookie_dfpi": {"dfpi-a", "dfpi-c"},
                "rookie_ancestor": {"ancestor-same_site", "ancestor-cross_site"},
            }
            expected_hosts = {
                "rookie_top": {"top.rookie-a.test", "other.rookie-c.test"},
                "rookie_chips": {"third.rookie-b.test"},
                "rookie_dfpi": {"third.rookie-b.test"},
                "rookie_ancestor": {"nested.rookie-a.test"},
            }
            if (
                name not in valid_values
                or value not in valid_values[name]
                or host not in expected_hosts[name]
            ):
                raise ActiveWriterError(
                    f"unexpected Firefox context identity/value: "
                    f"{host!r}/{name!r}={value!r}"
                )
            flat = {
                "domain": host,
                "path": str(row["path"]),
                "secure": bool(row["isSecure"]),
                "expires": _firefox_expiry(row["expiry"], schema_version),
                "name": name,
                "value": value,
                "http_only": bool(row["isHttpOnly"]),
                "same_site": int(row["sameSite"]),
            }
            context = {
                "top_frame_site_key": None,
                "has_cross_site_ancestor": None,
                "source_scheme": None,
                "source_port": None,
                "is_persistent": None,
                "origin_attributes": origin_attributes,
                "user_context_id": _unsigned(parsed, "userContextId"),
                "partition_key": parsed.get("partitionKey"),
                "private_browsing_id": _unsigned(parsed, "privateBrowsingId"),
            }
        detailed.append({"cookie": flat, "context": context})

    assert_ancestor_identities(detailed, engine, version)

    counts: dict[str, int] = {}
    for record in detailed:
        counts[record["cookie"]["name"]] = (
            counts.get(record["cookie"]["name"], 0) + 1
        )
    if counts != inventory["raw_rows_by_name"]:
        raise ActiveWriterError(
            f"raw {engine} context store ({version}) held {counts}; "
            f"partition_context_inventory.json expects {inventory['raw_rows_by_name']}"
        )

    contexts = send_view_contexts(
        top_origin=origins["top"],
        other_top_origin=origins["other_top"],
        third_origin=origins["third"],
        nested_origin=origins["nested"],
    )
    send_views = _expected_send_views(detailed, contexts, engine)
    by_name = {view["name"]: view for view in send_views}
    manifest = {
        "schema_version": 1,
        "tiers": ["partition_context"],
        "browser_version": browser_version,
        "identities": {
            "filtered_flat": ["domain", "path", "name"],
            "unfiltered_flat": ["domain", "path", "name"],
            "detailed": [
                "cookie.domain",
                "cookie.path",
                "cookie.name",
                "context.top_frame_site_key",
                "context.has_cross_site_ancestor",
                "context.source_scheme",
                "context.source_port",
                "context.is_persistent",
                "context.origin_attributes",
                "context.user_context_id",
                "context.partition_key",
                "context.private_browsing_id",
            ],
        },
        "expected": {
            "filtered_flat": [],
            "unfiltered_flat": [],
            "detailed": detailed,
        },
        "expected_headers": {
            "matching": by_name["matching"]["header_tokens"],
            "other_top_level_site": by_name["other_top_level_site"]["header_tokens"],
        },
        "expected_send_views": send_views,
        "expected_missing_selector": {
            "code": "incomplete_send_context",
            "required": _demanded_selectors(detailed, engine),
        },
    }
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def observed_browser_version(observed: Path) -> str | None:
    """Read the seeder's recorded browser version, for failure messages.

    A browser that does not record an ancestor chain is a fact about that
    build, so the raw-store oracle names the version in its error rather than
    reporting an anonymous count mismatch.
    """

    try:
        manifest = json.loads(observed.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    version = manifest.get("browser_version")
    return str(version) if isinstance(version, str) and version else None


def run(args: argparse.Namespace) -> None:
    sandbox = require_remote_sandbox(args.sandbox)
    profile, environment = discovery_layout(args.engine, sandbox)
    certificate, private_key = generate_certificate(sandbox)
    port = pick_port()
    server = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "tests/e2e/context_cookie_server.py",
            "--port",
            str(port),
            "--certificate",
            str(certificate),
            "--private-key",
            str(private_key),
            "--event-log",
            str(sandbox / "context-events.jsonl"),
        ],
        cwd=str(ROOT),
        env=environment,
    )
    top_origin = f"https://top.rookie-a.test:{port}"
    other_top_origin = f"https://other.rookie-c.test:{port}"
    third_origin = f"https://third.rookie-b.test:{port}"
    nested_origin = f"https://nested.rookie-a.test:{port}"
    observed = sandbox / f"{args.engine}-browser-observed.json"
    try:
        wait_for_https(port, server, args.timeout)
        seed = [
            "node",
            "tests/e2e/seed_partitioned_cookie.mjs",
            args.engine,
            str(profile),
            f"{top_origin}/top?third_origin={third_origin}&engine={args.engine}",
            str(observed),
        ]
        if args.xvfb:
            seed = ["xvfb-run", "-a", *seed]
        run_checked(seed, environment, "partition-seed")
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()

    database = database_for(args.engine, profile)
    raw_manifest = sandbox / f"{args.engine}-raw-context-manifest.json"
    write_raw_context_manifest(
        database,
        args.engine,
        raw_manifest,
        origins={
            "top": top_origin,
            "other_top": other_top_origin,
            "third": third_origin,
            "nested": nested_origin,
        },
        browser_version=observed_browser_version(observed),
    )
    os.environ.update(
        {
            key: value
            for key, value in environment.items()
            if key in {"HOME", "XDG_CONFIG_HOME", "LOCALAPPDATA", "APPDATA"}
        }
    )
    browser_id = "chromium" if args.engine == "chromium" else "firefox"
    profile_id = discovered_profile_id(args.engine, browser_id, database)
    environment.update(
        {
            "ROOKIE_E2E_CONTEXT_ENGINE": args.engine,
            "ROOKIE_E2E_CONTEXT_DB": str(database),
            "ROOKIE_E2E_CONTEXT_TOP_ORIGIN": top_origin,
            "ROOKIE_E2E_CONTEXT_OTHER_TOP_ORIGIN": other_top_origin,
            "ROOKIE_E2E_CONTEXT_THIRD_ORIGIN": third_origin,
            "ROOKIE_E2E_CONTEXT_NESTED_ORIGIN": nested_origin,
            "ROOKIE_E2E_CONTEXT_SOURCE_PORT": str(port),
            "ROOKIE_E2E_BROWSER_ID": browser_id,
            "ROOKIE_E2E_CONTEXT_MANIFEST": str(raw_manifest),
        }
    )
    python = venv_python()
    common = [
        "--engine",
        args.engine,
        "--database",
        str(database),
        "--browser-id",
        browser_id,
        "--top-origin",
        top_origin,
        "--other-top-origin",
        other_top_origin,
        "--third-origin",
        third_origin,
        "--nested-origin",
        nested_origin,
        "--source-port",
        str(port),
    ]
    run_checked(
        [str(python), "tests/e2e/assert_partitioned_context.py", *common],
        environment,
        "partition-python",
    )
    run_checked(
        [
            "node",
            "tests/e2e/assert_partitioned_context.mjs",
            args.engine,
            str(database),
            browser_id,
            top_origin,
            other_top_origin,
            third_origin,
            str(port),
            nested_origin,
        ],
        environment,
        "partition-node",
    )
    run_checked(
        [
            "cargo",
            "test",
            "--test",
            "e2e_context",
            "browser_produced_partition_context_survives_snapshot_and_header_filter",
            "--locked",
            "--",
            "--ignored",
            "--nocapture",
        ],
        environment,
        "partition-rust",
    )
    run_checked(
        [
            str(python),
            "tests/e2e/assert_partitioned_context_cli.py",
            *common,
            "--profile-id",
            profile_id,
            "--cli",
            str(ROOT / "target/release/rookie-cookies"),
        ],
        environment,
        "partition-cli",
    )
    print(
        "PARTITION_CONTEXT_PROOF "
        + json.dumps(
            {
                "engine": args.engine,
                "browser_id": browser_id,
                "profile_id": profile_id,
                "profile": str(profile),
                "database": str(database),
                "observed_manifest": str(observed),
                "raw_context_manifest": str(raw_manifest),
                "nested_origin": nested_origin,
                **schema_metadata(database, args.engine),
                "surfaces": ["rust", "python", "node", "cli"],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    emit_representative_depth(
        "partition_context",
        ("partitioned", "detailed", "discovery", "send_selection"),
        ("rust", "python", "node", "cli"),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--sandbox", type=Path, required=True)
    parser.add_argument("--xvfb", action="store_true")
    parser.add_argument("--timeout", type=float, default=120)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run(args)
    except (
        ActiveWriterError,
        OSError,
        sqlite3.Error,
        subprocess.CalledProcessError,
    ) as error:
        print(f"partition context E2E failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
