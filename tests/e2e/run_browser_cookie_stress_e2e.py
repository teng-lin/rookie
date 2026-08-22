#!/usr/bin/env python3
"""Run active-browser mutation/concurrency stress with exact postconditions."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
import time
from typing import Any, Sequence
from urllib.request import HTTPSHandler, build_opener

from run_active_writer_e2e import ActiveWriterError, ROOT, pick_port, venv_python


def require_ci_sandbox(path: Path) -> Path:
    if os.environ.get("CI", "").lower() != "true":
        raise ActiveWriterError("browser stress is restricted to isolated CI")
    runner_temp_raw = os.environ.get("RUNNER_TEMP")
    if not runner_temp_raw:
        raise ActiveWriterError("RUNNER_TEMP is required")
    runner_temp = Path(runner_temp_raw).resolve(strict=True)
    sandbox = path.resolve()
    try:
        sandbox.relative_to(runner_temp)
    except ValueError as error:
        raise ActiveWriterError(
            f"stress sandbox {sandbox} is outside RUNNER_TEMP"
        ) from error
    sandbox.mkdir(parents=True, exist_ok=True)
    return sandbox


def generate_certificate(sandbox: Path) -> tuple[Path, Path]:
    certificate = sandbox / "stress-cert.pem"
    private_key = sandbox / "stress-key.pem"
    names = ",".join(f"DNS:seed.rookie-{index}.test" for index in range(8))
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
            "/CN=rookie-stress-e2e",
            "-addext",
            f"subjectAltName={names}",
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
    opener = build_opener(HTTPSHandler(context=ssl._create_unverified_context()))
    deadline = time.monotonic() + timeout
    endpoint = f"https://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ActiveWriterError(f"stress HTTPS server exited {process.returncode}")
        try:
            with opener.open(endpoint, timeout=0.5) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise ActiveWriterError(f"stress HTTPS server did not bind {endpoint}")


def wait_for_ack(
    control: Path, sequence: int, seeder: subprocess.Popen[Any], timeout: float
) -> dict[str, Any]:
    path = control / f"ack-{sequence}.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if (
                payload.get("protocol_version") != 1
                or payload.get("sequence") != sequence
            ):
                raise ActiveWriterError(f"invalid stress acknowledgement: {payload!r}")
            return payload
        if seeder.poll() is not None:
            raise ActiveWriterError(
                f"stress seeder exited {seeder.returncode} before acknowledgement {sequence}"
            )
        time.sleep(0.1)
    raise ActiveWriterError(f"timed out waiting for stress acknowledgement {sequence}")


def command(control: Path, sequence: int, action: str, **values: Any) -> None:
    target = control / f"command-{sequence}.json"
    temporary = target.with_suffix(f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps({"sequence": sequence, "action": action, **values}) + "\n",
        encoding="utf-8",
    )
    temporary.replace(target)


def database_for(engine: str, profile: Path) -> Path:
    if engine == "firefox":
        return (profile / "cookies.sqlite").resolve(strict=True)
    for relative in ("Default/Network/Cookies", "Default/Cookies"):
        candidate = profile / relative
        if candidate.is_file():
            return candidate.resolve()
    raise ActiveWriterError(f"no Chromium cookie database below {profile}")


def wait_for_stress_rows(database: Path, engine: str, timeout: float) -> None:
    table = "cookies" if engine == "chromium" else "moz_cookies"
    deadline = time.monotonic() + timeout
    last_count = -1
    while time.monotonic() < deadline:
        try:
            connection = sqlite3.connect(
                database.resolve().as_uri() + "?mode=ro", uri=True
            )
            try:
                last_count = int(
                    connection.execute(
                        f"select count(*) from {table} where name like 'stress_%'"
                    ).fetchone()[0]
                )
            finally:
                connection.close()
            if last_count == 320:
                return
        except sqlite3.Error:
            pass
        time.sleep(0.2)
    raise ActiveWriterError(
        f"stress database retained {last_count} rows instead of 320"
    )


def wait_for_mutation(
    database: Path, engine: str, round_number: int, timeout: float
) -> None:
    table = "cookies" if engine == "chromium" else "moz_cookies"
    added = [f"stress_{index}_round_{round_number}" for index in range(8)]
    deleted = [f"stress_{index}_{round_number + 1}" for index in range(8)]
    candidates = added + deleted
    placeholders = ",".join("?" for _ in candidates)
    deadline = time.monotonic() + timeout
    last_names: list[str] = []
    while time.monotonic() < deadline:
        try:
            connection = sqlite3.connect(
                database.resolve().as_uri() + "?mode=ro", uri=True
            )
            try:
                last_names = [
                    str(row[0])
                    for row in connection.execute(
                        f"select name from {table} where name in ({placeholders})",
                        candidates,
                    )
                ]
            finally:
                connection.close()
            if all(name in last_names for name in added) and all(
                name not in last_names for name in deleted
            ):
                return
        except sqlite3.Error:
            pass
        time.sleep(0.2)
    raise ActiveWriterError(
        f"stress mutation {round_number} was not durable; observed {sorted(last_names)}"
    )


def surface_commands(
    engine: str, database: Path, python: Path
) -> list[tuple[str, list[str]]]:
    browser_id = "chromium" if engine == "chromium" else "firefox"
    python_command = [
        str(python),
        "tests/e2e/stress_surface_python.py",
        "--engine",
        engine,
        "--database",
        str(database),
        "--browser-id",
        browser_id,
        "--projection",
        "detailed",
    ]
    node_command = [
        "node",
        "tests/e2e/stress_surface_node.mjs",
        engine,
        str(database),
        browser_id,
        "detailed",
    ]
    rust_command = [
        str(ROOT / "target/release/examples/e2e_cookie_surface"),
        engine,
        str(database),
        browser_id,
        "detailed",
    ]
    cli_command = [
        str(ROOT / "target/release/rookie-cookies"),
        "from-path",
        str(database),
        "--format",
        "detailed",
    ]
    if engine == "chromium":
        cli_command.extend(["--browser-id", browser_id])
    return [
        ("python", python_command),
        ("node", node_command),
        ("rust", rust_command),
        ("cli", cli_command),
    ]


def verify_all_surfaces(
    manifest: Path,
    engine: str,
    database: Path,
    *,
    workers: int,
    iterations: int,
    phase: str,
) -> None:
    python = venv_python()
    for surface, extraction in surface_commands(engine, database, python):
        stress = [
            str(python),
            "tests/e2e/run_cookie_stress.py",
            "--manifest",
            str(manifest),
            "--projection",
            "detailed",
            "--surface",
            f"{phase}-{surface}",
            "--workers",
            str(workers),
            "--iterations",
            str(iterations),
            "--",
            *extraction,
        ]
        print("+", " ".join(stress), flush=True)
        subprocess.run(stress, cwd=str(ROOT), check=True, timeout=600)


def assert_immediate_timeout(engine: str, database: Path) -> None:
    command_line = [
        str(ROOT / "target/release/rookie-cookies"),
        "from-path",
        str(database),
        "--format",
        "detailed",
        "--timeout-secs",
        "0",
    ]
    if engine == "chromium":
        command_line.extend(["--browser-id", "chromium"])
    completed = subprocess.run(
        command_line,
        cwd=str(ROOT),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode == 0:
        raise ActiveWriterError("zero-second stress extraction unexpectedly completed")
    print(
        "STRESS_TIMEOUT_PROOF "
        + json.dumps(
            {
                "engine": engine,
                "returncode": completed.returncode,
                "message": (completed.stderr or completed.stdout).strip(),
            },
            sort_keys=True,
        ),
        flush=True,
    )


def run(args: argparse.Namespace) -> None:
    sandbox = require_ci_sandbox(args.sandbox)
    profile = sandbox / "profile"
    profile.mkdir(parents=True, exist_ok=True)
    (profile / ".rookie-cookie-fixture-source.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "rookie-cookie-fixture-source",
                "source_kind": "disposable_e2e_profile",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    control = sandbox / "control"
    control.mkdir()
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
        ],
        cwd=str(ROOT),
    )
    seeder: subprocess.Popen[str] | None = None
    try:
        wait_for_https(port, server, args.timeout)
        initial_manifest = sandbox / "manifest-0.json"
        seed = [
            "node",
            "tests/e2e/seed_cookie_stress.mjs",
            args.engine,
            str(profile),
            str(port),
            str(initial_manifest),
            "seed",
            "0",
            str(control),
        ]
        if args.xvfb:
            seed = ["xvfb-run", "-a", *seed]
        seeder = subprocess.Popen(seed, cwd=str(ROOT), text=True)
        ready = wait_for_ack(control, 0, seeder, args.timeout)
        database = database_for(args.engine, profile)
        wait_for_stress_rows(database, args.engine, args.timeout)
        print(f"STRESS_ACTIVE_PROOF {json.dumps(ready, sort_keys=True)}", flush=True)
        verify_all_surfaces(
            initial_manifest,
            args.engine,
            database,
            workers=args.workers,
            iterations=args.iterations,
            phase="seed-open",
        )
        assert_immediate_timeout(args.engine, database)

        sequence = 1
        final_manifest = initial_manifest
        for round_number in range(args.rounds):
            final_manifest = sandbox / f"manifest-{sequence}.json"
            command(
                control,
                sequence,
                "mutate",
                round=round_number,
                manifest=str(final_manifest),
            )
            ack = wait_for_ack(control, sequence, seeder, args.timeout)
            wait_for_stress_rows(database, args.engine, args.timeout)
            wait_for_mutation(database, args.engine, round_number, args.timeout)
            print(f"STRESS_ACTIVE_PROOF {json.dumps(ack, sort_keys=True)}", flush=True)
            verify_all_surfaces(
                final_manifest,
                args.engine,
                database,
                workers=args.workers,
                iterations=args.iterations,
                phase=f"mutation-{round_number}-open",
            )
            sequence += 1

        command(control, sequence, "close")
        wait_for_ack(control, sequence, seeder, args.timeout)
        seeder.wait(timeout=args.timeout)
        if seeder.returncode != 0:
            raise ActiveWriterError(f"stress seeder exited {seeder.returncode}")
        verify_all_surfaces(
            final_manifest,
            args.engine,
            database,
            workers=1,
            iterations=1,
            phase="closed-final",
        )
        print(
            f"browser stress passed: engine={args.engine} rows=320 "
            f"rounds={args.rounds} concurrent_surfaces=4",
            flush=True,
        )
    finally:
        if seeder is not None and seeder.poll() is None:
            seeder.terminate()
            try:
                seeder.wait(timeout=10)
            except subprocess.TimeoutExpired:
                seeder.kill()
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--sandbox", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--xvfb", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run(args)
    except (
        ActiveWriterError,
        json.JSONDecodeError,
        OSError,
        sqlite3.Error,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"browser stress E2E failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
