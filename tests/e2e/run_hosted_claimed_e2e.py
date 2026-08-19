#!/usr/bin/env python3
"""Seed an installed claimed browser and extract rookie_ci=bar.

Chromium-family browsers are driven through Playwright + executablePath.
Gecko forks are launched with --headless --profile (Playwright's Firefox
is a patched build and cannot drive LibreWolf/Zen).
"""

from __future__ import annotations

import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def wait_for_server(url: str = "http://127.0.0.1:8765/", timeout: float = 15) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 8765), timeout=0.5):
                return
        except OSError:
            time.sleep(0.25)
    raise SystemExit(f"cookie server did not become ready at {url}")


def venv_python() -> Path:
    unix = ROOT / ".venv" / "bin" / "python"
    windows = ROOT / ".venv" / "Scripts" / "python.exe"
    if unix.is_file():
        return unix
    if windows.is_file():
        return windows
    raise SystemExit("expected a .venv from the workflow's maturin develop step")


def plant_keychain() -> None:
    service = os.environ.get("ROOKIE_E2E_KEYCHAIN_SERVICE")
    if not service or sys.platform != "darwin":
        return
    account = os.environ.get("ROOKIE_E2E_KEYCHAIN_ACCOUNT", "Chrome")
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


def seed_chromium(channel: str, user_data: Path, url: str) -> None:
    cmd = ["node", str(ROOT / "tests/e2e/seed_chromium_cookie.mjs"), channel, str(user_data), url]
    if sys.platform.startswith("linux") and shutil.which("xvfb-run"):
        cmd = ["xvfb-run", "-a", *cmd]
    subprocess.run(cmd, check=True, cwd=str(ROOT))


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
    subprocess.run([str(py), str(ROOT / "tests/e2e/assert_chrome_cookie.py")], check=True, env=env)
    subprocess.run(["node", str(ROOT / "tests/e2e/assert_chrome_cookie.mjs")], check=True, env=env, cwd=str(ROOT))
    db = find_chromium_db(user_data)
    cli = [str(py), str(ROOT / "tests/e2e/assert_cli_cookie.py"), str(db)]
    if sys.platform == "win32":
        cli.extend(["--key-path", str(user_data / "Local State")])
    else:
        cli.extend(["--browser-id", browser_id])
    subprocess.run(cli, check=True, env=env)


def assert_gecko(profile: Path) -> None:
    env = os.environ.copy()
    env["ROOKIE_E2E_FIREFOX_PROFILE"] = str(profile)
    py = venv_python()
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


def run() -> int:
    browser = os.environ.get("ROOKIE_E2E_BROWSER_ID", "")
    engine = os.environ.get("ROOKIE_E2E_ENGINE", "chromium")
    exe = os.environ.get("ROOKIE_E2E_BROWSER_PATH", "")
    if not browser or not exe:
        raise SystemExit("ROOKIE_E2E_BROWSER_ID and ROOKIE_E2E_BROWSER_PATH must be set")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ROOT))
    user_data = Path(
        os.environ.get("ROOKIE_E2E_USER_DATA_DIR", workspace / ".rookie-ci" / browser)
    )
    user_data.mkdir(parents=True, exist_ok=True)

    plant_keychain()
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "tests/e2e/cookie_server.py")],
        cwd=str(ROOT),
    )
    try:
        wait_for_server()
        url = "http://127.0.0.1:8765/set"
        if engine == "gecko":
            seed_gecko(exe, user_data, url)
            assert_gecko(user_data)
        else:
            os.environ["ROOKIE_E2E_BROWSER_PATH"] = exe
            seed_chromium("chromium", user_data, url)
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
