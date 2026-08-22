#!/usr/bin/env python3
"""Run active-browser mutation/concurrency stress with exact postconditions."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import signal
import sqlite3
import ssl
import subprocess
import sys
import time
from typing import Any, Sequence
from urllib.request import HTTPSHandler, build_opener

from browser_coverage_contract import emit_representative_depth
from run_active_writer_e2e import (
    ActiveWriterError,
    ROOT,
    database_metadata,
    pick_port,
    venv_python,
)


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
                payload.get("protocolVersion") != 1
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


def process_is_alive(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except OSError:
        return False
    return True


def validate_stress_profile_proof(
    payload: dict[str, Any],
    *,
    engine: str,
    sequence: int,
    phase: str,
    profile: Path,
    database: Path,
    churn_active: bool,
    manifest: Path | None,
) -> None:
    expected = {
        "protocolVersion": 1,
        "sequence": sequence,
        "phase": phase,
        "engine": engine,
        "profileDir": str(profile.resolve(strict=True)),
        "databasePath": str(database.resolve(strict=True)),
    }
    mismatches = {
        field: (value, payload.get(field))
        for field, value in expected.items()
        if payload.get(field) != value
    }
    if mismatches:
        raise ActiveWriterError(f"stress ownership proof mismatch: {mismatches}")
    if manifest is not None and payload.get("manifest") != str(manifest.resolve()):
        raise ActiveWriterError("stress acknowledgement named the wrong manifest")
    seeder_pid = payload.get("seederPid")
    browser_pids = payload.get("browserProcessIds")
    if not isinstance(seeder_pid, int) or seeder_pid <= 0:
        raise ActiveWriterError("stress acknowledgement lacked a valid seeder PID")
    if (
        not isinstance(browser_pids, list)
        or not browser_pids
        or any(not isinstance(pid, int) or pid <= 0 for pid in browser_pids)
        or seeder_pid in browser_pids
    ):
        raise ActiveWriterError(
            f"stress acknowledgement lacked distinct browser PIDs: {browser_pids!r}"
        )
    # Renderer and utility processes are intentionally short-lived. The proof
    # only needs at least one acknowledged browser process to remain alive;
    # requiring every PID sampled by the seeder makes a healthy browser fail
    # when Chromium retires a renderer between acknowledgement and validation.
    if not any(process_is_alive(pid) for pid in browser_pids):
        raise ActiveWriterError(
            f"no acknowledged stress browser PID was alive: {browser_pids!r}"
        )
    liveness = payload.get("liveness")
    if not isinstance(liveness, dict):
        raise ActiveWriterError("stress acknowledgement lacked browser liveness")
    if liveness.get("readyState") not in {"interactive", "complete"}:
        raise ActiveWriterError(f"stress page was not live: {liveness!r}")
    if liveness.get("cookieCount") != 320:
        raise ActiveWriterError(f"stress browser count was not exact: {liveness!r}")
    churn = liveness.get("writeChurn")
    if (
        not isinstance(churn, dict)
        or churn.get("active") is not churn_active
        or not isinstance(churn.get("requests"), int)
        or churn["requests"] < 8
    ):
        raise ActiveWriterError(f"stress write-churn proof was invalid: {churn!r}")


def raw_write_generation(database: Path, engine: str) -> int:
    if engine == "firefox":
        # Firefox commonly holds an exclusive SQLite lock while open. Its WAL
        # or rollback journal mtime is still an observable raw-storage write
        # generation and does not require bypassing the browser's lock.
        candidates = [database, Path(f"{database}-wal"), Path(f"{database}-journal")]
        generations = [
            candidate.stat().st_mtime_ns for candidate in candidates if candidate.is_file()
        ]
        if not generations:
            raise ActiveWriterError("stress database lacked a raw write generation")
        return max(generations)
    table, column = (
        ("cookies", "last_access_utc")
        if engine == "chromium"
        else ("moz_cookies", "lastAccessed")
    )
    connection = sqlite3.connect(
        database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.1
    )
    try:
        row = connection.execute(
            f"select max({column}) from {table} where name like 'stress_%'"
        ).fetchone()
    finally:
        connection.close()
    if row is None or not isinstance(row[0], int):
        raise ActiveWriterError("stress database lacked a raw write generation")
    return row[0]


def wait_for_write_generation(
    database: Path, engine: str, previous: int, timeout: float
) -> int:
    deadline = time.monotonic() + timeout
    latest = previous
    while time.monotonic() < deadline:
        try:
            latest = raw_write_generation(database, engine)
            if latest > previous:
                return latest
        except sqlite3.Error:
            pass
        time.sleep(0.05)
    raise ActiveWriterError(
        f"browser write churn did not advance raw last-access state beyond {previous}; "
        f"last={latest}"
    )


def wait_for_stress_rows(
    database: Path,
    engine: str,
    timeout: float,
    *,
    allow_locked_after: float = 1,
) -> None:
    table = "cookies" if engine == "chromium" else "moz_cookies"
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    last_count = -1
    while time.monotonic() < deadline:
        try:
            connection = sqlite3.connect(
                database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.1
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
        except sqlite3.Error as error:
            if (
                engine == "firefox"
                and "locked" in str(error).lower()
                and time.monotonic() - started >= allow_locked_after
            ):
                print(
                    "STRESS_RAW_STORE "
                    + json.dumps(
                        {
                            "database": str(database),
                            "engine": engine,
                            "state": "browser-locked",
                            "browser_probe_authoritative": True,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return
        time.sleep(0.2)
    raise ActiveWriterError(
        f"stress database retained {last_count} rows instead of 320"
    )


def wait_for_mutation(
    database: Path,
    engine: str,
    round_number: int,
    timeout: float,
    *,
    allow_locked_after: float = 1,
) -> None:
    table = "cookies" if engine == "chromium" else "moz_cookies"
    added = [f"stress_{index}_round_{round_number}" for index in range(8)]
    deleted = [f"stress_{index}_{round_number + 1}" for index in range(8)]
    candidates = added + deleted
    placeholders = ",".join("?" for _ in candidates)
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    last_names: list[str] = []
    while time.monotonic() < deadline:
        try:
            connection = sqlite3.connect(
                database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.1
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
        except sqlite3.Error as error:
            if (
                engine == "firefox"
                and "locked" in str(error).lower()
                and time.monotonic() - started >= allow_locked_after
            ):
                print(
                    "STRESS_RAW_MUTATION "
                    + json.dumps(
                        {
                            "database": str(database),
                            "engine": engine,
                            "round": round_number,
                            "state": "browser-locked",
                            "browser_probe_authoritative": True,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return
        time.sleep(0.2)
    raise ActiveWriterError(
        f"stress mutation {round_number} was not durable; observed {sorted(last_names)}"
    )


def surface_commands(
    engine: str, database: Path, python: Path, browser_id: str | None = None
) -> list[tuple[str, list[str]]]:
    browser_id = browser_id or ("chromium" if engine == "chromium" else "firefox")
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
    browser_id: str | None = None,
) -> None:
    python = venv_python()
    commands: list[tuple[str, list[str]]] = []
    for surface, extraction in surface_commands(engine, database, python, browser_id):
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
        commands.append((surface, stress))

    def run_surface(surface: str, command_line: list[str]) -> str:
        print("+", " ".join(command_line), flush=True)
        subprocess.run(command_line, cwd=str(ROOT), check=True, timeout=600)
        return surface

    completed_surfaces: list[str] = []
    with ThreadPoolExecutor(max_workers=len(commands)) as executor:
        futures = [
            executor.submit(run_surface, surface, command_line)
            for surface, command_line in commands
        ]
        for future in as_completed(futures):
            completed_surfaces.append(future.result())
    if sorted(completed_surfaces) != sorted(surface for surface, _ in commands):
        raise ActiveWriterError(
            f"mixed-surface stress did not complete every surface: {completed_surfaces}"
        )


def cli_from_path_command(
    engine: str,
    database: Path,
    *,
    browser_id: str,
    timeout_seconds: int,
) -> list[str]:
    command_line = [
        str(ROOT / "target/release/rookie-cookies"),
        "from-path",
        str(database),
        "--format",
        "detailed",
        "--timeout-secs",
        str(timeout_seconds),
    ]
    if engine == "chromium":
        command_line.extend(["--browser-id", browser_id])
    return command_line


def locked_database_copy(database: Path, target: Path) -> sqlite3.Connection:
    source = sqlite3.connect(
        database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5
    )
    destination = sqlite3.connect(target, isolation_level=None, timeout=0)
    try:
        source.backup(destination)
        mode = str(destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0])
        if mode.lower() != "delete":
            raise ActiveWriterError(
                f"locked-store copy selected journal mode {mode!r}, expected delete"
            )
        destination.execute("BEGIN EXCLUSIVE")
    except BaseException:
        destination.close()
        raise
    finally:
        source.close()
    return destination


def require_typed_stop(
    completed: subprocess.CompletedProcess[str], *, reason: str
) -> str:
    message = (completed.stderr or completed.stdout).strip()
    expected = {
        "timeout": "operation timed out",
        "cancellation": "operation was cancelled",
    }[reason]
    if completed.returncode == 0 or expected not in message.lower():
        raise ActiveWriterError(
            f"locked-store {reason} was not typed ({completed.returncode}): {message}"
        )
    return message


def assert_locked_store_controls(
    *,
    engine: str,
    database: Path,
    manifest: Path,
    sandbox: Path,
    browser_id: str,
) -> None:
    locked = sandbox / f"locked-{engine}.sqlite"
    lock = locked_database_copy(database, locked)
    cancellation: subprocess.Popen[str] | None = None
    try:
        timeout_result = subprocess.run(
            cli_from_path_command(
                engine,
                locked,
                browser_id=browser_id,
                timeout_seconds=1,
            ),
            cwd=str(ROOT),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        timeout_message = require_typed_stop(timeout_result, reason="timeout")

        cancellation = subprocess.Popen(
            cli_from_path_command(
                engine,
                locked,
                browser_id=browser_id,
                timeout_seconds=60,
            ),
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.25)
        if cancellation.poll() is not None:
            stdout, stderr = cancellation.communicate()
            raise ActiveWriterError(
                "locked-store extraction exited before cancellation: "
                f"{(stderr or stdout).strip()}"
            )
        cancellation.send_signal(signal.SIGINT)
        stdout, stderr = cancellation.communicate(timeout=15)
        cancellation_message = require_typed_stop(
            subprocess.CompletedProcess(
                cancellation.args,
                cancellation.returncode,
                stdout,
                stderr,
            ),
            reason="cancellation",
        )
    finally:
        if cancellation is not None and cancellation.poll() is None:
            cancellation.kill()
            cancellation.wait(timeout=5)
        lock.execute("ROLLBACK")
        lock.close()

    verify_all_surfaces(
        manifest,
        engine,
        locked,
        workers=1,
        iterations=1,
        phase="locked-store-recovered",
        browser_id=browser_id,
    )
    print(
        "STRESS_LOCK_CONTROL_PROOF "
        + json.dumps(
            {
                "engine": engine,
                "database": str(locked),
                "timeout": timeout_message,
                "cancellation": cancellation_message,
                "recovered_exactly": True,
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
        validate_stress_profile_proof(
            ready,
            engine=args.engine,
            sequence=0,
            phase="ready",
            profile=profile,
            database=database,
            churn_active=True,
            manifest=initial_manifest,
        )
        wait_for_stress_rows(database, args.engine, args.timeout)
        print(f"STRESS_ACTIVE_PROOF {json.dumps(ready, sort_keys=True)}", flush=True)
        print(
            "STRESS_DATABASE_PROOF "
            + json.dumps(
                {
                    "engine": args.engine,
                    "profile": str(profile.resolve(strict=True)),
                    "database": str(database),
                    **database_metadata(database, args.engine),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        generation = raw_write_generation(database, args.engine)
        verify_all_surfaces(
            initial_manifest,
            args.engine,
            database,
            workers=args.workers,
            iterations=args.iterations,
            phase="seed-open",
            browser_id=args.browser_id,
        )
        generation = wait_for_write_generation(
            database, args.engine, generation, args.timeout
        )
        print(
            f"STRESS_WRITE_GENERATION engine={args.engine} value={generation}",
            flush=True,
        )
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
            validate_stress_profile_proof(
                ack,
                engine=args.engine,
                sequence=sequence,
                phase="mutated",
                profile=profile,
                database=database,
                churn_active=True,
                manifest=final_manifest,
            )
            wait_for_stress_rows(database, args.engine, args.timeout)
            wait_for_mutation(database, args.engine, round_number, args.timeout)
            print(f"STRESS_ACTIVE_PROOF {json.dumps(ack, sort_keys=True)}", flush=True)
            generation = raw_write_generation(database, args.engine)
            verify_all_surfaces(
                final_manifest,
                args.engine,
                database,
                workers=args.workers,
                iterations=args.iterations,
                phase=f"mutation-{round_number}-open",
                browser_id=args.browser_id,
            )
            generation = wait_for_write_generation(
                database, args.engine, generation, args.timeout
            )
            print(
                f"STRESS_WRITE_GENERATION engine={args.engine} round={round_number} "
                f"value={generation}",
                flush=True,
            )
            sequence += 1

        closed_manifest = sandbox / f"manifest-{sequence}-closed.json"
        command(control, sequence, "close", manifest=str(closed_manifest))
        closing = wait_for_ack(control, sequence, seeder, args.timeout)
        validate_stress_profile_proof(
            closing,
            engine=args.engine,
            sequence=sequence,
            phase="closing",
            profile=profile,
            database=database,
            churn_active=False,
            manifest=closed_manifest,
        )
        seeder.wait(timeout=args.timeout)
        if seeder.returncode != 0:
            raise ActiveWriterError(f"stress seeder exited {seeder.returncode}")
        final_manifest = closed_manifest
        verify_all_surfaces(
            final_manifest,
            args.engine,
            database,
            workers=1,
            iterations=1,
            phase="closed-final",
            browser_id=args.browser_id,
        )
        assert_locked_store_controls(
            engine=args.engine,
            database=database,
            manifest=final_manifest,
            sandbox=sandbox,
            browser_id=args.browser_id,
        )
        print(
            f"browser stress passed: engine={args.engine} rows=320 "
            f"rounds={args.rounds} concurrent_surfaces=4",
            flush=True,
        )
        emit_representative_depth(
            "nightly_stress",
            ("exact_set", "active_writer", "detailed"),
            ("rust", "python", "node", "cli"),
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
    parser.add_argument("--browser-id")
    parser.add_argument("--sandbox", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--xvfb", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.browser_id is None:
        args.browser_id = "chromium" if args.engine == "chromium" else "firefox"
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
