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
            "subjectAltName=DNS:top.rookie-a.test,DNS:other.rookie-c.test,DNS:third.rookie-b.test",
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


def write_raw_context_manifest(database: Path, engine: str, output: Path) -> None:
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

    expected_count = 5 if engine == "chromium" else 7
    if len(rows) != expected_count:
        raise ActiveWriterError(
            f"raw {engine} context store contained {len(rows)} rookie rows; "
            f"expected {expected_count}"
        )

    detailed: list[dict[str, Any]] = []
    for row in rows:
        if engine == "chromium":
            top_key_raw = row["top_frame_site_key"]
            top_key = str(top_key_raw) if top_key_raw not in (None, "") else None
            name = str(row["name"])
            host = str(row["host_key"])
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
                    bool(row["has_cross_site_ancestor"])
                    if "has_cross_site_ancestor" in columns
                    else None
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
            }
            expected_hosts = {
                "rookie_top": {"top.rookie-a.test", "other.rookie-c.test"},
                "rookie_chips": {"third.rookie-b.test"},
                "rookie_dfpi": {"third.rookie-b.test"},
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

    matching = ["rookie_chips=partition-a", "rookie_chips=unpartitioned"]
    other = ["rookie_chips=partition-c", "rookie_chips=unpartitioned"]
    if engine == "firefox":
        matching.append("rookie_dfpi=dfpi-a")
        other.append("rookie_dfpi=dfpi-c")
    manifest = {
        "schema_version": 1,
        "tiers": ["partition_context"],
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
            "matching": sorted(matching),
            "other_top_level_site": sorted(other),
        },
    }
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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
    write_raw_context_manifest(database, args.engine, raw_manifest)
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
                **schema_metadata(database, args.engine),
                "surfaces": ["rust", "python", "node", "cli"],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    emit_representative_depth(
        "partition_context",
        ("partitioned", "detailed", "discovery"),
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
