#!/usr/bin/env python3
"""Seed an installed claimed browser and extract rookie_ci=bar.

Installed Chromium-family browsers are launched through their native headless
CLI. Playwright explicitly does not guarantee arbitrary executablePath builds,
and a branded browser can hang before its control pipe becomes ready even when
the browser has successfully started. Gecko forks use their native CLI too.
Safari and IE use their image-provided vendor WebDriver servers.
"""

from __future__ import annotations

import os
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from webdriver_cookie import (
    file_snapshot,
    seed_with_startup_retry,
    wait_for_changed_cookie_file,
)


ROOT = Path(__file__).resolve().parents[2]


def pick_cookie_port() -> int:
    raw = os.environ.get("ROOKIE_E2E_COOKIE_PORT")
    if raw:
        return int(raw)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_server(
    port: int,
    proc: subprocess.Popen[bytes] | subprocess.Popen[str],
    log_path: Path,
    timeout: float = 45,
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            logs = log_path.read_text(encoding="utf-8", errors="replace")
            raise SystemExit(
                f"cookie server exited {proc.returncode} before binding "
                f"127.0.0.1:{port}\n{logs}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.25)
    logs = (
        log_path.read_text(encoding="utf-8", errors="replace")
        if log_path.is_file()
        else ""
    )
    raise SystemExit(
        f"cookie server did not become ready at http://127.0.0.1:{port}/\n{logs}"
    )


def start_cookie_server() -> tuple[subprocess.Popen[str], int, Path]:
    port = pick_cookie_port()
    env = os.environ.copy()
    env["ROOKIE_E2E_COOKIE_PORT"] = str(port)
    log_path = Path(tempfile.gettempdir()) / f"rookie-cookie-server-{port}.log"
    with log_path.open("w", encoding="utf-8") as log_handle:
        proc = subprocess.Popen(
            [sys.executable, "-u", str(ROOT / "tests/e2e/cookie_server.py")],
            cwd=str(ROOT),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
    wait_for_server(port, proc, log_path)
    return proc, port, log_path


def venv_python() -> Path:
    unix = ROOT / ".venv" / "bin" / "python"
    windows = ROOT / ".venv" / "Scripts" / "python.exe"
    if unix.is_file():
        return unix
    if windows.is_file():
        return windows
    raise SystemExit("expected a .venv from the workflow's maturin develop step")


def keychain_accounts(service: str) -> list[str]:
    raw = os.environ.get("ROOKIE_E2E_KEYCHAIN_ACCOUNT", "Chrome")
    accounts = [part.strip() for part in raw.split(",") if part.strip()]
    if service == "Chrome Safe Storage":
        for extra in ("Chrome", "Chromium"):
            if extra not in accounts:
                accounts.append(extra)
    return accounts


def plant_keychain() -> None:
    service = os.environ.get("ROOKIE_E2E_KEYCHAIN_SERVICE")
    if not service or sys.platform != "darwin":
        return
    for account in keychain_accounts(service):
        subprocess.run(
            [
                "/usr/bin/security",
                "delete-generic-password",
                "-a",
                account,
                "-s",
                service,
            ],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/security",
                "add-generic-password",
                "-U",
                "-a",
                account,
                "-s",
                service,
                "-w",
                "mock_password",
            ],
            check=True,
        )


def stage_chromium_user_data(user_data: Path) -> None:
    user_data.mkdir(parents=True, exist_ok=True)
    # Some Chromium forks read these first-run files before writing cookies.
    for name in ("search_engines.json", "search_engines_prompt.json"):
        path = user_data / name
        if not path.exists():
            path.write_text("{}\n", encoding="utf-8")


def cookies_db_has_name(user_data: Path, name: str = "rookie_ci") -> bool:
    try:
        db = find_chromium_db(user_data)
    except SystemExit:
        return False
    try:
        connection = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            row = connection.execute(
                "select 1 from cookies where name = ? limit 1", (name,)
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return False
    return row is not None


def chromium_native_command(
    exe: str,
    user_data: Path,
    url: str,
    *,
    platform: str | None = None,
    has_xvfb: bool | None = None,
) -> list[str]:
    platform = platform or sys.platform
    has_xvfb = shutil.which("xvfb-run") is not None if has_xvfb is None else has_xvfb
    screenshot = Path(tempfile.gettempdir()) / "rookie-claimed-seed.png"
    cmd = [
        exe,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--disable-default-apps",
        f"--user-data-dir={user_data}",
        f"--screenshot={screenshot}",
        "--virtual-time-budget=8000",
        "--dump-dom",
        url,
    ]
    if platform.startswith("linux"):
        cmd.insert(-1, "--password-store=gnome-libsecret")
        if has_xvfb:
            cmd = ["xvfb-run", "-a", *cmd]
    return cmd


def seed_chromium_native(exe: str, user_data: Path, url: str) -> None:
    cmd = chromium_native_command(exe, user_data, url)
    print("+", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, cwd=str(ROOT))
    saw_cookie = False
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            if cookies_db_has_name(user_data):
                saw_cookie = True
                time.sleep(1)
                break
            if proc.poll() is not None:
                break
            time.sleep(0.5)
        if not saw_cookie:
            status = proc.poll()
            if status is not None:
                raise SystemExit(
                    f"native chromium seed exited {status} without writing rookie_ci"
                )
            raise SystemExit("native chromium seed timed out without writing rookie_ci")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    if not cookies_db_has_name(user_data):
        raise SystemExit("native chromium seed did not persist rookie_ci")


def seed_gecko(exe: str, profile: Path, url: str) -> None:
    profile.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "--headless", "--no-remote", "--profile", str(profile), url]
    if sys.platform.startswith("linux") and shutil.which("xvfb-run"):
        cmd = ["xvfb-run", "-a", *cmd]
    env = os.environ.copy()
    env["MOZ_HEADLESS"] = "1"
    print("+", " ".join(cmd), flush=True)
    try:
        subprocess.run(cmd, check=False, cwd=str(ROOT), env=env, timeout=90)
    except subprocess.TimeoutExpired:
        pass
    cookies = profile / "cookies.sqlite"
    if not cookies.is_file():
        raise SystemExit(f"gecko seed did not write {cookies}")


def find_chromium_db(user_data: Path) -> Path:
    for rel in ("Default/Network/Cookies", "Default/Cookies"):
        candidate = user_data / rel
        if candidate.is_file():
            return candidate
    raise SystemExit(f"no Chromium Cookies db under {user_data}")


def assert_chromium(user_data: Path, browser_id: str) -> None:
    env = os.environ.copy()
    env["ROOKIE_E2E_USER_DATA_DIR"] = str(user_data)
    env["ROOKIE_E2E_BROWSER_ID"] = browser_id
    py = venv_python()
    subprocess.run(
        [
            "cargo",
            "test",
            "--test",
            "e2e_chrome",
            "--locked",
            "--",
            "--ignored",
            "--nocapture",
        ],
        check=True,
        env=env,
        cwd=str(ROOT),
    )
    subprocess.run(
        [str(py), str(ROOT / "tests/e2e/assert_chrome_cookie.py")], check=True, env=env
    )
    subprocess.run(
        ["node", str(ROOT / "tests/e2e/assert_chrome_cookie.mjs")],
        check=True,
        env=env,
        cwd=str(ROOT),
    )
    db = find_chromium_db(user_data)
    cli = [str(py), str(ROOT / "tests/e2e/assert_cli_cookie.py"), str(db)]
    if sys.platform == "win32":
        cli.extend(["--local-state-path", str(user_data / "Local State")])
    else:
        cli.extend(["--browser-id", browser_id])
    subprocess.run(cli, check=True, env=env)


def assert_gecko(profile: Path) -> None:
    env = os.environ.copy()
    env["ROOKIE_E2E_FIREFOX_PROFILE"] = str(profile)
    py = venv_python()
    subprocess.run(
        [
            "cargo",
            "test",
            "--test",
            "e2e_firefox",
            "--locked",
            "--",
            "--ignored",
            "--nocapture",
        ],
        check=True,
        env=env,
        cwd=str(ROOT),
    )
    subprocess.run(
        [str(py), str(ROOT / "tests/e2e/assert_firefox_cookie.py")],
        check=True,
        env=env,
    )
    subprocess.run(
        ["node", str(ROOT / "tests/e2e/assert_firefox_cookie.mjs")],
        check=True,
        env=env,
        cwd=str(ROOT),
    )
    subprocess.run(
        [
            str(py),
            str(ROOT / "tests/e2e/assert_cli_cookie.py"),
            str(profile / "cookies.sqlite"),
        ],
        check=True,
        env=env,
    )


def assert_native(cookie_file: Path, browser: str) -> None:
    env = os.environ.copy()
    env["ROOKIE_E2E_COOKIE_DB"] = str(cookie_file)
    env["ROOKIE_E2E_BROWSER_ID"] = browser
    py = venv_python()
    subprocess.run(
        [
            "cargo",
            "test",
            "--test",
            "e2e_native",
            "--locked",
            "--",
            "--ignored",
            "--nocapture",
        ],
        check=True,
        env=env,
        cwd=str(ROOT),
    )
    subprocess.run(
        [str(py), str(ROOT / "tests/e2e/assert_native_cookie.py")],
        check=True,
        env=env,
        cwd=str(ROOT),
    )
    subprocess.run(
        ["node", str(ROOT / "tests/e2e/assert_native_cookie.mjs")],
        check=True,
        env=env,
        cwd=str(ROOT),
    )
    subprocess.run(
        [
            str(py),
            str(ROOT / "tests/e2e/assert_cli_cookie.py"),
            str(cookie_file),
        ],
        check=True,
        env=env,
        cwd=str(ROOT),
    )


def run() -> int:
    browser = os.environ.get("ROOKIE_E2E_BROWSER_ID", "")
    engine = os.environ.get("ROOKIE_E2E_ENGINE", "chromium")
    exe = os.environ.get("ROOKIE_E2E_BROWSER_PATH", "")
    if not browser or not exe:
        raise SystemExit(
            "ROOKIE_E2E_BROWSER_ID and ROOKIE_E2E_BROWSER_PATH must be set"
        )
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ROOT))
    user_data = Path(
        os.environ.get("ROOKIE_E2E_USER_DATA_DIR", workspace / ".rookie-ci" / browser)
    )
    user_data.mkdir(parents=True, exist_ok=True)

    server, port, _log_path = start_cookie_server()
    try:
        plant_keychain()
        url = f"http://127.0.0.1:{port}/set"
        if engine == "gecko":
            seed_gecko(exe, user_data, url)
            assert_gecko(user_data)
        elif engine in ("safari", "internet_explorer"):
            before = file_snapshot(engine)
            seed_with_startup_retry(engine, exe, url)
            cookie_file = wait_for_changed_cookie_file(engine, before)
            os.environ["ROOKIE_E2E_COOKIE_DB"] = str(cookie_file)
            print(f"native cookie store: {cookie_file}", flush=True)
            assert_native(cookie_file, browser)
        else:
            os.environ["ROOKIE_E2E_BROWSER_PATH"] = exe
            stage_chromium_user_data(user_data)
            seed_chromium_native(exe, user_data, url)
            assert_chromium(user_data, browser)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    print(f"hosted claimed e2e ok: {browser} ({engine})")
    return 0


def main() -> int:
    if sys.platform.startswith("linux") and not os.environ.get("ROOKIE_E2E_DBUS"):
        # Re-exec inside a session bus + unlocked gnome-keyring, same as e2e.yml.
        inner = (
            'eval "$(printf "\\n" | gnome-keyring-daemon --unlock || true)"; '
            'eval "$(gnome-keyring-daemon --start --components=secrets || true)"; '
            "export XDG_CURRENT_DESKTOP=GNOME ROOKIE_E2E_DBUS=1; "
            "exec "
            f"{shlex.quote(sys.executable)} "
            f"{shlex.quote(str(Path(__file__).resolve()))}"
        )
        os.execvp("dbus-run-session", ["dbus-run-session", "--", "bash", "-lc", inner])
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
