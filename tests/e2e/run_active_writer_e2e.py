#!/usr/bin/env python3
"""Run real-browser extraction against an actively owned profile database.

This coordinator is intentionally limited to workspace-scoped Playwright
profiles supplied by CI. It never discovers or reads an installed user's
default browser profile.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
BASELINE_REQUIRED = {"rookie_ci": "before", "rookie_remove": "present"}
BASELINE_FORBIDDEN = ["rookie_added"]
MUTATED_REQUIRED = {"rookie_added": "present", "rookie_ci": "after"}
MUTATED_FORBIDDEN = ["rookie_remove"]


class ActiveWriterError(RuntimeError):
    """Protocol, proof, or extraction failure."""


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_server(port: int, process: subprocess.Popen[Any], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    endpoint = f"http://127.0.0.1:{port}/"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ActiveWriterError(
                f"cookie server exited with status {process.returncode}"
            )
        try:
            with urlopen(endpoint, timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise ActiveWriterError(f"cookie server did not bind {endpoint}")


def wait_for_ack(
    control_dir: Path,
    sequence: int,
    seeder: subprocess.Popen[Any],
    timeout: float,
) -> dict[str, Any]:
    ack_path = control_dir / f"ack-{sequence}.json"
    error_path = control_dir / "error.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if error_path.is_file():
            payload = json.loads(error_path.read_text(encoding="utf-8"))
            raise ActiveWriterError(f"browser seeder failed: {payload.get('message')}")
        if ack_path.is_file():
            payload = json.loads(ack_path.read_text(encoding="utf-8"))
            if payload.get("protocolVersion") != 1:
                raise ActiveWriterError(f"unsupported seeder ack: {payload}")
            if payload.get("sequence") != sequence:
                raise ActiveWriterError(f"ack sequence mismatch: {payload}")
            return payload
        if seeder.poll() is not None:
            raise ActiveWriterError(
                f"browser seeder exited {seeder.returncode} before ack {sequence}"
            )
        time.sleep(0.1)
    raise ActiveWriterError(f"timed out waiting for browser ack {sequence}")


def send_command(control_dir: Path, sequence: int, action: str) -> None:
    atomic_write_json(
        control_dir / f"command-{sequence}.json",
        {"protocolVersion": 1, "sequence": sequence, "action": action},
    )


def expected_database(engine: str, profile: Path) -> Path:
    if engine == "chromium":
        return profile / "Default" / "Network" / "Cookies"
    return profile / "cookies.sqlite"


def process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        process_query_limited_information = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
            process_query_limited_information, False, pid
        )
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def validate_profile_proof(
    ack: dict[str, Any],
    engine: str,
    profile: Path,
    seeder: subprocess.Popen[Any],
    *,
    expected_phase: str = "ready",
) -> Path:
    if seeder.poll() is not None:
        raise ActiveWriterError("seeder is not alive at the open-profile checkpoint")
    if ack.get("engine") != engine or ack.get("phase") != expected_phase:
        raise ActiveWriterError(f"unexpected {expected_phase} acknowledgement: {ack}")
    resolved_profile = profile.resolve(strict=True)
    acknowledged_profile = Path(str(ack.get("profileDir"))).resolve(strict=True)
    if acknowledged_profile != resolved_profile:
        raise ActiveWriterError(
            f"seeder profile mismatch: {acknowledged_profile} != {resolved_profile}"
        )
    database = Path(str(ack.get("databasePath"))).resolve(strict=True)
    expected = expected_database(engine, resolved_profile).resolve(strict=True)
    if database != expected:
        raise ActiveWriterError(
            f"seeder database mismatch: {database} != active profile DB {expected}"
        )
    try:
        database.relative_to(resolved_profile)
    except ValueError as error:
        raise ActiveWriterError(
            f"active database escaped the workspace profile: {database}"
        ) from error
    acknowledged_pid = ack.get("seederPid")
    if not isinstance(acknowledged_pid, int) or not process_is_alive(acknowledged_pid):
        raise ActiveWriterError(
            f"acknowledged seeder PID is not alive: {acknowledged_pid}"
        )
    if not isinstance(ack.get("liveness"), dict):
        raise ActiveWriterError("ready ack omitted the browser liveness probe")
    browser_process_ids = ack.get("browserProcessIds")
    if not isinstance(browser_process_ids, list) or not browser_process_ids:
        raise ActiveWriterError(
            "ready ack did not identify a browser process owning the supplied profile"
        )
    if not all(isinstance(pid, int) and pid > 0 for pid in browser_process_ids):
        raise ActiveWriterError(
            f"ready ack contained invalid browser process IDs: {browser_process_ids!r}"
        )
    if not any(process_is_alive(pid) for pid in browser_process_ids):
        raise ActiveWriterError(
            f"no acknowledged browser process is alive: {browser_process_ids!r}"
        )
    return database


def database_metadata(
    database: Path, engine: str, timeout: float = 10
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: sqlite3.Error | None = None
    while True:
        try:
            uri = f"{database.resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=1)
            try:
                journal_mode = str(
                    connection.execute("pragma journal_mode").fetchone()[0]
                )
                schema_version = int(
                    connection.execute("pragma schema_version").fetchone()[0]
                )
                user_version = int(
                    connection.execute("pragma user_version").fetchone()[0]
                )
                browser_schema_version: int | None = None
                if engine == "chromium":
                    row = connection.execute(
                        "select value from meta where key = 'version'"
                    ).fetchone()
                    if row is not None:
                        browser_schema_version = int(row[0])
            finally:
                connection.close()
            break
        except sqlite3.Error as error:
            last_error = error
            if time.monotonic() >= deadline:
                raise ActiveWriterError(
                    f"could not inspect active database metadata: {last_error}"
                ) from error
            time.sleep(0.1)
    return {
        "journalMode": journal_mode,
        "sqliteSchemaVersion": schema_version,
        "sqliteUserVersion": user_version,
        "browserSchemaVersion": browser_schema_version,
        "walPresent": Path(f"{database}-wal").is_file(),
        "journalPresent": Path(f"{database}-journal").is_file(),
        "sharedMemoryPresent": Path(f"{database}-shm").is_file(),
    }


def wait_for_storage_names(
    database: Path,
    engine: str,
    required: dict[str, str],
    forbidden: list[str],
    timeout: float,
) -> None:
    table = "cookies" if engine == "chromium" else "moz_cookies"
    expected_names = set(required)
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            uri = f"{database.resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=1)
            try:
                rows = connection.execute(
                    f"select name from {table} where name in ({','.join('?' for _ in expected_names | set(forbidden))})",
                    sorted(expected_names | set(forbidden)),
                ).fetchall()
            finally:
                connection.close()
            names = [str(row[0]) for row in rows]
            if all(names.count(name) == 1 for name in expected_names) and all(
                name not in names for name in forbidden
            ):
                return
        except sqlite3.Error as error:
            last_error = error
        time.sleep(0.2)
    detail = f"; last SQLite error: {last_error}" if last_error else ""
    raise ActiveWriterError(
        f"active {engine} store did not persist required={sorted(expected_names)} "
        f"forbidden={forbidden} within {timeout}s{detail}"
    )


def venv_python() -> Path:
    candidates = [ROOT / ".venv/bin/python", ROOT / ".venv/Scripts/python.exe"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ActiveWriterError("expected the workflow-created .venv")


def run_checked(command: Sequence[str], env: dict[str, str], phase: str) -> None:
    print(f"[{phase}] + {' '.join(command)}", flush=True)
    subprocess.run(
        list(command),
        cwd=str(ROOT),
        env=env,
        check=True,
        timeout=240,
    )


def assertion_environment(
    engine: str,
    profile: Path,
    database: Path,
    browser_id: str,
    required: dict[str, str],
    forbidden: list[str],
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ROOKIE_E2E_COOKIE_DB": str(database),
            "ROOKIE_E2E_COOKIE_NAME": "rookie_ci",
            "ROOKIE_E2E_COOKIE_VALUE": required["rookie_ci"],
            "ROOKIE_E2E_REQUIRED_COOKIES_JSON": json.dumps(
                required, sort_keys=True, separators=(",", ":")
            ),
            "ROOKIE_E2E_FORBIDDEN_COOKIES_JSON": json.dumps(
                forbidden, separators=(",", ":")
            ),
            "ROOKIE_E2E_EXACT_COOKIE_STATE": "1",
            "ROOKIE_E2E_CHECK_BROWSER_DISCOVERY": "0",
        }
    )
    if engine == "chromium":
        env["ROOKIE_E2E_USER_DATA_DIR"] = str(profile)
        env["ROOKIE_E2E_BROWSER_ID"] = browser_id
    else:
        env["ROOKIE_E2E_FIREFOX_PROFILE"] = str(profile)
    return env


def run_surface_assertions(
    engine: str,
    profile: Path,
    database: Path,
    browser_id: str,
    required: dict[str, str],
    forbidden: list[str],
    phase: str,
) -> None:
    env = assertion_environment(
        engine, profile, database, browser_id, required, forbidden
    )
    python = venv_python()
    if engine == "chromium":
        rust_filter = {
            "linux": "extracts_seeded_cookie_from_chrome_libsecret_profile",
            "darwin": "extracts_seeded_cookie_through_real_macos_keychain_provider",
            "win32": "extracts_seeded_cookie_from_chrome_dpapi_profile",
        }[sys.platform]
        run_checked(
            [
                "cargo",
                "test",
                "--test",
                "e2e_chrome",
                "--locked",
                "--",
                rust_filter,
                "--ignored",
                "--nocapture",
            ],
            env,
            phase,
        )
        run_checked([str(python), "tests/e2e/assert_chrome_cookie.py"], env, phase)
        run_checked(["node", "tests/e2e/assert_chrome_cookie.mjs"], env, phase)
        cli = [str(python), "tests/e2e/assert_cli_cookie.py", str(database)]
        if sys.platform == "win32":
            cli.extend(["--local-state-path", str(profile / "Local State")])
        else:
            cli.extend(["--browser-id", browser_id])
        run_checked(cli, env, phase)
    else:
        run_checked(
            [
                "cargo",
                "test",
                "--test",
                "e2e_firefox",
                "--locked",
                "--",
                "extracts_seeded_cookie_from_firefox_profile",
                "--ignored",
                "--nocapture",
            ],
            env,
            phase,
        )
        run_checked([str(python), "tests/e2e/assert_firefox_cookie.py"], env, phase)
        run_checked(["node", "tests/e2e/assert_firefox_cookie.mjs"], env, phase)
        run_checked(
            [str(python), "tests/e2e/assert_cli_cookie.py", str(database)],
            env,
            phase,
        )


def build_seeder_command(
    engine: str,
    profile: Path,
    baseline_url: str,
    control_dir: Path,
    channel: str,
    xvfb: bool,
) -> list[str]:
    if engine == "chromium":
        command = [
            "node",
            "tests/e2e/seed_chromium_cookie.mjs",
            channel,
            str(profile),
            baseline_url,
            str(control_dir),
        ]
    else:
        command = [
            "node",
            "tests/e2e/seed_firefox_cookie.mjs",
            str(profile),
            baseline_url,
            str(control_dir),
        ]
    if xvfb:
        if shutil.which("xvfb-run") is None:
            raise ActiveWriterError("--xvfb requested but xvfb-run is unavailable")
        command = ["xvfb-run", "-a", *command]
    return command


def log_checkpoint(
    label: str,
    ack: dict[str, Any],
    database: Path,
    engine: str,
    seeder: subprocess.Popen[Any],
) -> None:
    proof = {
        "checkpoint": label,
        "browserState": "open" if seeder.poll() is None else "closed",
        "seederPid": seeder.pid,
        "browserProcessIds": ack.get("browserProcessIds", []),
        "browserVersion": ack.get("browserVersion"),
        "profileDir": ack.get("profileDir"),
        "databasePath": str(database),
        "databaseOwnedByAcknowledgedProfile": True,
        **database_metadata(database, engine),
    }
    print(f"ACTIVE_WRITER_PROOF {json.dumps(proof, sort_keys=True)}", flush=True)


def run(args: argparse.Namespace) -> None:
    profile = args.profile.resolve()
    profile.mkdir(parents=True, exist_ok=True)
    control_parent = Path(
        tempfile.mkdtemp(
            prefix="rookie-active-writer-", dir=os.environ.get("RUNNER_TEMP")
        )
    )
    control_dir = control_parent / "control"
    control_dir.mkdir()
    port = pick_port()
    server_log = control_parent / "cookie-server.log"
    seeder_log = control_parent / "browser-seeder.log"
    server_env = os.environ.copy()
    server_env["ROOKIE_E2E_COOKIE_PORT"] = str(port)
    server_env["ROOKIE_E2E_REQUEST_LOG"] = str(control_parent / "requests.log")
    server_handle = server_log.open("w", encoding="utf-8")
    seeder_handle = seeder_log.open("w", encoding="utf-8")
    server = subprocess.Popen(
        [sys.executable, "-u", "tests/e2e/cookie_server.py"],
        cwd=str(ROOT),
        env=server_env,
        stdout=server_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    seeder: subprocess.Popen[str] | None = None
    try:
        wait_for_server(port, server, args.timeout)
        baseline_url = f"http://127.0.0.1:{port}/active-writer/baseline"
        command = build_seeder_command(
            args.engine,
            profile,
            baseline_url,
            control_dir,
            args.channel,
            args.xvfb,
        )
        print("+", " ".join(command), flush=True)
        seeder = subprocess.Popen(
            command,
            cwd=str(ROOT),
            env=os.environ.copy(),
            stdout=seeder_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        ready = wait_for_ack(control_dir, 0, seeder, args.timeout)
        database = validate_profile_proof(ready, args.engine, profile, seeder)
        wait_for_storage_names(
            database,
            args.engine,
            BASELINE_REQUIRED,
            BASELINE_FORBIDDEN,
            args.timeout,
        )
        log_checkpoint("open-baseline", ready, database, args.engine, seeder)
        if args.engine == "chromium" and sys.platform == "win32":
            run_checked(
                [
                    str(venv_python()),
                    "tests/e2e/inspect_chromium_profile.py",
                    str(profile),
                    "--cookie-name",
                    "rookie_ci",
                    "--expected-prefix",
                    "v10",
                    "--require-dpapi-key",
                ],
                os.environ.copy(),
                "open-baseline-crypto-proof",
            )
        run_surface_assertions(
            args.engine,
            profile,
            database,
            args.browser_id,
            BASELINE_REQUIRED,
            BASELINE_FORBIDDEN,
            "open-baseline",
        )

        send_command(control_dir, 1, "mutate")
        mutated = wait_for_ack(control_dir, 1, seeder, args.timeout)
        mutated_database = validate_profile_proof(
            mutated,
            args.engine,
            profile,
            seeder,
            expected_phase="mutated",
        )
        if mutated_database != database:
            raise ActiveWriterError("mutated checkpoint changed active database")
        wait_for_storage_names(
            database,
            args.engine,
            MUTATED_REQUIRED,
            MUTATED_FORBIDDEN,
            args.timeout,
        )
        log_checkpoint("open-mutated", mutated, database, args.engine, seeder)
        run_surface_assertions(
            args.engine,
            profile,
            database,
            args.browser_id,
            MUTATED_REQUIRED,
            MUTATED_FORBIDDEN,
            "open-mutated",
        )

        # This browser-side probe occurs after every open-profile extraction,
        # proving the extractor did not terminate or disconnect the writer.
        send_command(control_dir, 2, "probe")
        probed = wait_for_ack(control_dir, 2, seeder, args.timeout)
        probed_database = validate_profile_proof(
            probed,
            args.engine,
            profile,
            seeder,
            expected_phase="probed",
        )
        if probed_database != database:
            raise ActiveWriterError("liveness checkpoint changed active database")
        log_checkpoint("post-extraction-probe", probed, database, args.engine, seeder)

        send_command(control_dir, 3, "close")
        closed = wait_for_ack(control_dir, 3, seeder, args.timeout)
        seeder.wait(timeout=args.timeout)
        if seeder.returncode != 0:
            raise ActiveWriterError(f"browser seeder exited {seeder.returncode}")
        print(
            f"ACTIVE_WRITER_PROOF {json.dumps({'checkpoint': 'closed', 'browserState': 'closed', 'databasePath': str(database), 'ack': closed}, sort_keys=True)}",
            flush=True,
        )
        run_surface_assertions(
            args.engine,
            profile,
            database,
            args.browser_id,
            MUTATED_REQUIRED,
            MUTATED_FORBIDDEN,
            "closed-final",
        )
        print(
            "active-writer transition verified: add + replace + delete while open; "
            "post-extraction liveness probe passed; closed snapshot matched",
            flush=True,
        )
    except Exception:
        server_handle.flush()
        seeder_handle.flush()
        print(f"cookie server log: {server_log}", file=sys.stderr)
        print(f"browser seeder log: {seeder_log}", file=sys.stderr)
        if seeder_log.is_file():
            print(
                seeder_log.read_text(encoding="utf-8", errors="replace"),
                file=sys.stderr,
            )
        raise
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
        server_handle.close()
        seeder_handle.close()
        if not args.keep_artifacts:
            shutil.rmtree(control_parent, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, choices=("chromium", "firefox"))
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--channel", default="chrome")
    parser.add_argument("--browser-id", default="chrome")
    parser.add_argument("--xvfb", action="store_true")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--keep-artifacts", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run(args)
    except (
        ActiveWriterError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"active-writer e2e failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
