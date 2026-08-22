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
from urllib.request import HTTPSHandler, build_opener

from run_active_writer_e2e import (
    ActiveWriterError,
    ROOT,
    pick_port,
    run_checked,
    venv_python,
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


def discovery_layout(engine: str, sandbox: Path) -> tuple[Path, dict[str, str]]:
    isolated_home = sandbox / "home"
    config_home = isolated_home / ".config"
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(isolated_home),
            "XDG_CONFIG_HOME": str(config_home),
            "LOCALAPPDATA": str(isolated_home / "AppData/Local"),
            "APPDATA": str(isolated_home / "AppData/Roaming"),
        }
    )
    if engine == "chromium":
        profile = config_home / "chromium"
    else:
        root = isolated_home / "snap/firefox/common/.mozilla/firefox"
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
            Path(source["path"]).resolve() == database for source in profile["sources"]
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
                **schema_metadata(database, args.engine),
                "surfaces": ["rust", "python", "node", "cli"],
            },
            sort_keys=True,
        ),
        flush=True,
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
