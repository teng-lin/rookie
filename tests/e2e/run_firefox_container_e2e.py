#!/usr/bin/env python3
"""Prove browser-produced Firefox Multi-Account Container persistence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from typing import Sequence
from urllib.parse import parse_qsl

from browser_coverage_contract import emit_representative_depth
from cookie_manifest import ManifestError, load_manifest, verify_records
from run_active_writer_e2e import ActiveWriterError, ROOT, run_checked, venv_python
from run_partition_context_e2e import (
    MARKER,
    _firefox_expiry,
    database_for,
    discovered_profile_id,
    playwright_executable,
    require_remote_sandbox,
    schema_metadata,
)
from run_exact_corpus_e2e import isolated_environment, stage_discovered_profile


FIREFOX_CONTAINER_EXTENSION = Path(__file__).with_name("firefox_container_extension")
FIREFOX_CONTAINER_NAME = "rookie-e2e-container"


def container_cookie_present(database: Path) -> bool:
    """Return whether Firefox has committed the container seed to its store."""

    if not database.is_file():
        return False
    try:
        connection = sqlite3.connect(
            database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0
        )
    except sqlite3.Error:
        return False
    try:
        return (
            connection.execute(
                "select 1 from moz_cookies where name = 'rookie_container' limit 1"
            ).fetchone()
            is not None
        )
    except sqlite3.Error:
        return False
    finally:
        connection.close()


def seed_container_with_web_ext(
    profile: Path,
    environment: dict[str, str],
    sandbox: Path,
    *,
    xvfb: bool,
    timeout: float = 120,
) -> None:
    """Load the unsigned test extension temporarily into the disposable profile."""

    web_ext = ROOT / "tests/e2e/node_modules/.bin/web-ext"
    if not web_ext.is_file():
        raise ActiveWriterError(
            "web-ext is required for the Firefox container lane; install web-ext@10.6.0"
        )
    browser = environment.get("ROOKIE_E2E_BROWSER_PATH")
    if not browser or not Path(browser).is_file():
        raise ActiveWriterError("container lane lacks an explicit Firefox executable")
    command = [
        str(web_ext),
        "run",
        "--source-dir",
        str(FIREFOX_CONTAINER_EXTENSION),
        "--artifacts-dir",
        str(sandbox / "web-ext-artifacts"),
        "--firefox",
        browser,
        "--firefox-profile",
        str(profile),
        "--keep-profile-changes",
        "--profile-create-if-missing",
        "--no-reload",
        "--no-input",
        "--no-config-discovery",
        "--start-url",
        "about:blank",
    ]
    if xvfb:
        command = ["xvfb-run", "-a", *command]
    process = subprocess.Popen(command, cwd=str(ROOT), env=environment, text=True)
    containers = profile / "containers.json"
    deadline = time.monotonic() + timeout
    observed = False
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ActiveWriterError(
                    f"web-ext exited {process.returncode} before creating the container"
                )
            try:
                payload = json.loads(containers.read_text(encoding="utf-8"))
                observed = any(
                    identity.get("name") == FIREFOX_CONTAINER_NAME
                    and int(identity.get("userContextId", 0)) > 0
                    for identity in payload.get("identities", [])
                )
            except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
                observed = False
            if observed and container_cookie_present(profile / "cookies.sqlite"):
                break
            time.sleep(0.1)
        if not observed:
            raise ActiveWriterError("Firefox did not create the disposable container")
        if not container_cookie_present(profile / "cookies.sqlite"):
            raise ActiveWriterError("Firefox container cookie never reached the store")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)




def write_container_manifest(database: Path, output: Path) -> int:
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        schema_version = int(connection.execute("pragma user_version").fetchone()[0])
        rows = connection.execute(
            "select * from moz_cookies where name = 'rookie_container'"
        ).fetchall()
    finally:
        connection.close()
    if len(rows) != 1:
        raise ActiveWriterError(
            f"Firefox persisted {len(rows)} rookie_container rows, expected one"
        )
    row = rows[0]
    origin_attributes = str(row["originAttributes"] or "")
    attributes = dict(parse_qsl(origin_attributes.removeprefix("^")))
    try:
        user_context_id = int(attributes["userContextId"])
    except (KeyError, ValueError) as error:
        raise ActiveWriterError(
            f"browser container lacked a numeric userContextId: {origin_attributes!r}"
        ) from error
    if (
        user_context_id <= 0
        or "partitionKey" in attributes
        or int(attributes.get("privateBrowsingId", "0")) != 0
    ):
        raise ActiveWriterError(
            f"browser container had unexpected isolation attributes: {origin_attributes!r}"
        )
    flat = {
        "domain": str(row["host"]),
        "path": str(row["path"]),
        "secure": bool(row["isSecure"]),
        "expires": _firefox_expiry(row["expiry"], schema_version),
        "name": str(row["name"]),
        "value": str(row["value"]),
        "http_only": bool(row["isHttpOnly"]),
        "same_site": int(row["sameSite"]),
    }
    expected_flat = {
        "domain": "container.rookie.test",
        "path": "/",
        "secure": True,
        "name": "rookie_container",
        "value": "container-1",
        "http_only": True,
        "same_site": 1,
    }
    wrong = {
        field: (expected, flat.get(field))
        for field, expected in expected_flat.items()
        if flat.get(field) != expected
    }
    if wrong or flat["expires"] <= 0:
        raise ActiveWriterError(
            f"raw Firefox container cookie disagreed with its seed: {wrong}, "
            f"expires={flat['expires']}"
        )
    detailed = {
        "cookie": flat,
        "context": {
            "top_frame_site_key": None,
            "has_cross_site_ancestor": None,
            "source_scheme": None,
            "source_port": None,
            "is_persistent": None,
            "origin_attributes": origin_attributes,
            "user_context_id": user_context_id,
            "partition_key": None,
            "private_browsing_id": (
                int(attributes["privateBrowsingId"])
                if "privateBrowsingId" in attributes
                else None
            ),
        },
    }
    manifest = {
        "schema_version": 1,
        "tiers": ["firefox_container"],
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
            "filtered_flat": [flat],
            "unfiltered_flat": [flat],
            "detailed": [detailed],
        },
    }
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return user_context_id


def detailed_commands(database: Path) -> list[tuple[str, list[str]]]:
    return [
        (
            "python",
            [
                str(venv_python()),
                "tests/e2e/stress_surface_python.py",
                "--engine",
                "firefox",
                "--database",
                str(database),
                "--browser-id",
                "firefox",
                "--projection",
                "detailed",
            ],
        ),
        (
            "node",
            [
                "node",
                "tests/e2e/stress_surface_node.mjs",
                "firefox",
                str(database),
                "firefox",
                "detailed",
            ],
        ),
        (
            "rust",
            [
                str(ROOT / "target/release/examples/e2e_cookie_surface"),
                "firefox",
                str(database),
                "firefox",
                "detailed",
            ],
        ),
        (
            "cli",
            [
                str(ROOT / "target/release/rookie-cookies"),
                "from-path",
                str(database),
                "--format",
                "detailed",
            ],
        ),
    ]


def verify_detailed_surfaces(
    database: Path, manifest_path: Path, environment: dict[str, str]
) -> None:
    manifest = load_manifest(manifest_path)
    for surface, command in detailed_commands(database):
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=240,
        )
        try:
            records = json.loads(completed.stdout)
            verify_records(
                manifest,
                "detailed",
                records,
                surface=f"{surface} Firefox container",
            )
        except (json.JSONDecodeError, ManifestError) as error:
            raise ActiveWriterError(
                f"{surface} Firefox container detailed mismatch: {error}"
            ) from error


def verify_cli_headers(
    *,
    profile_id: str,
    user_context_id: int,
    environment: dict[str, str],
) -> None:
    cli = str(ROOT / "target/release/rookie-cookies")
    base = [
        cli,
        "header",
        "--url",
        "https://container.rookie.test/",
        "--browser",
        "firefox",
        "--profile",
        profile_id,
        "--top-level-site",
        "https://container.rookie.test/",
    ]
    matching = subprocess.run(
        [*base, "--user-context-id", str(user_context_id)],
        cwd=str(ROOT),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if matching.stdout.strip() != "rookie_container=container-1":
        raise ActiveWriterError(f"CLI container header mismatch: {matching.stdout!r}")
    other = subprocess.run(
        [*base, "--user-context-id", str(user_context_id + 1)],
        cwd=str(ROOT),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if other.stdout.strip():
        raise ActiveWriterError(f"CLI leaked another container: {other.stdout!r}")
    missing = subprocess.run(
        base,
        cwd=str(ROOT),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    message = missing.stderr or missing.stdout
    if missing.returncode == 0 or "user_context_id" not in message:
        raise ActiveWriterError(
            f"CLI missing-container selector was not typed: {missing.returncode}: {message}"
        )


def run(args: argparse.Namespace) -> None:
    sandbox = require_remote_sandbox(args.sandbox)
    profile = sandbox / "seed-profile"
    profile.mkdir()
    (profile / ".rookie-cookie-fixture-source.json").write_text(
        json.dumps(MARKER, sort_keys=True) + "\n", encoding="utf-8"
    )
    environment = os.environ.copy()
    environment.update(isolated_environment(sandbox / "seed-runtime"))
    environment["ROOKIE_E2E_BROWSER_PATH"] = playwright_executable("firefox")
    seed_container_with_web_ext(
        profile,
        environment,
        sandbox,
        xvfb=args.xvfb,
    )
    profile, discovery_environment, expected_profile_id = stage_discovered_profile(
        "firefox", "firefox", profile
    )
    environment.update(discovery_environment)
    database = database_for("firefox", profile)
    manifest = sandbox / "firefox-container-raw-manifest.json"
    user_context_id = write_container_manifest(database, manifest)
    os.environ.update(
        {
            key: value
            for key, value in environment.items()
            if key in {"HOME", "XDG_CONFIG_HOME", "LOCALAPPDATA", "APPDATA"}
        }
    )
    profile_id = discovered_profile_id("firefox", "firefox", database)
    if profile_id != expected_profile_id:
        raise ActiveWriterError(
            f"container profile identity mismatch: {profile_id} != {expected_profile_id}"
        )
    environment.update(
        {
            "ROOKIE_E2E_CONTEXT_DB": str(database),
            "ROOKIE_E2E_CONTEXT_MANIFEST": str(manifest),
            "ROOKIE_E2E_USER_CONTEXT_ID": str(user_context_id),
        }
    )
    verify_detailed_surfaces(database, manifest, environment)
    run_checked(
        [
            str(venv_python()),
            "tests/e2e/assert_firefox_container.py",
            str(database),
            str(user_context_id),
        ],
        environment,
        "firefox-container-python-header",
    )
    run_checked(
        [
            "node",
            "tests/e2e/assert_firefox_container.mjs",
            str(database),
            str(user_context_id),
        ],
        environment,
        "firefox-container-node-header",
    )
    run_checked(
        [
            "cargo",
            "test",
            "--test",
            "e2e_context",
            "browser_produced_firefox_container_survives_snapshot_and_header_filter",
            "--locked",
            "--",
            "--ignored",
            "--nocapture",
        ],
        environment,
        "firefox-container-rust-header",
    )
    verify_cli_headers(
        profile_id=profile_id,
        user_context_id=user_context_id,
        environment=environment,
    )
    print(
        "FIREFOX_CONTAINER_PROOF "
        + json.dumps(
            {
                "profile": str(profile),
                "profile_id": profile_id,
                "database": str(database),
                "extension": str(FIREFOX_CONTAINER_EXTENSION),
                "extension_install": "web-ext-temporary",
                "user_context_id": user_context_id,
                "raw_manifest": str(manifest),
                "surfaces": ["rust", "python", "node", "cli"],
                **schema_metadata(database, "firefox"),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    emit_representative_depth(
        "firefox_container",
        ("partitioned", "detailed", "discovery"),
        ("rust", "python", "node", "cli"),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox", required=True, type=Path)
    parser.add_argument("--xvfb", action="store_true")
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
        subprocess.TimeoutExpired,
    ) as error:
        print(f"Firefox container E2E failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
