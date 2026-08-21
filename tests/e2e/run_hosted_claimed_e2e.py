#!/usr/bin/env python3
"""Seed an installed claimed browser and extract rookie_ci=bar.

Installed Chromium-family browsers are launched through their native headless
CLI. Playwright explicitly does not guarantee arbitrary executablePath builds,
and a branded browser can hang before its control pipe becomes ready even when
the browser has successfully started. Gecko forks use their native CLI too.
Safari launches the normal system application so the seed reaches its
persistent profile; IE uses a pinned 32-bit IEDriver server in Edge IE mode.
"""

from __future__ import annotations

import json
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
from urllib.request import urlopen

from webdriver_cookie import (
    WebDriverError,
    file_snapshot,
    seed_with_startup_retry,
    stop_browser,
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


def start_cookie_server() -> tuple[subprocess.Popen[str], int, Path, Path]:
    port = pick_cookie_port()
    env = os.environ.copy()
    env["ROOKIE_E2E_COOKIE_PORT"] = str(port)
    log_path = Path(tempfile.gettempdir()) / f"rookie-cookie-server-{port}.log"
    request_log = Path(tempfile.gettempdir()) / f"rookie-cookie-requests-{port}.log"
    request_log.write_text("", encoding="utf-8")
    env["ROOKIE_E2E_REQUEST_LOG"] = str(request_log)
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
    return proc, port, log_path, request_log


def safari_open_command(browser: str, url: str) -> list[str]:
    binary = Path(browser)
    app = next((parent for parent in binary.parents if parent.suffix == ".app"), None)
    if app is None:
        raise SystemExit(f"Safari executable is not inside an app bundle: {browser}")
    return ["/usr/bin/open", "-b", "com.apple.Safari", url]


def stop_safari(*, graceful: bool) -> None:
    # Ask Safari to checkpoint its normal persistent cookie store before the
    # hard process cleanup used to keep hosted runs independent.
    if graceful:
        try:
            subprocess.run(
                ["/usr/bin/osascript", "-e", 'tell application "Safari" to quit'],
                check=False,
                capture_output=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            pass
    subprocess.run(["pkill", "-x", "Safari"], check=False, capture_output=True)


def wait_for_request(request_log: Path, path: str, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests = request_log.read_text(encoding="utf-8").splitlines()
        except OSError:
            requests = []
        if path in requests:
            return
        time.sleep(0.25)
    raise SystemExit(f"Safari never requested {path}; observed requests: {requests!r}")


def seed_safari_native(
    browser: str,
    url: str,
    before: dict[Path, tuple[int, int]],
    request_log: Path,
) -> Path:
    stop_safari(graceful=False)
    command = safari_open_command(browser, url)
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, timeout=30)
    try:
        wait_for_request(request_log, "/set")
        cookie_file = wait_for_changed_cookie_file("safari", before, timeout=45)
    except WebDriverError:
        # Some Safari releases checkpoint BinaryCookies only on a graceful
        # application quit. Retry the same snapshot after asking it to quit.
        stop_safari(graceful=True)
        return wait_for_changed_cookie_file("safari", before, timeout=20)
    else:
        stop_safari(graceful=True)
        return cookie_file
    finally:
        stop_safari(graceful=False)


def venv_python() -> Path:
    unix = ROOT / ".venv" / "bin" / "python"
    windows = ROOT / ".venv" / "Scripts" / "python.exe"
    if unix.is_file():
        return unix
    if windows.is_file():
        return windows
    raise SystemExit("expected a .venv from the workflow's maturin develop step")


def keychain_accounts() -> list[str]:
    raw = os.environ.get("ROOKIE_E2E_KEYCHAIN_ACCOUNT", "Chrome")
    return [part.strip() for part in raw.split(",") if part.strip()]


def plant_keychain() -> None:
    service = os.environ.get("ROOKIE_E2E_KEYCHAIN_SERVICE")
    if not service or sys.platform != "darwin":
        return
    for account in keychain_accounts():
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
                # The CI keychain contains only this known test password. Let
                # the freshly installed browser read it without an interactive
                # macOS ACL prompt, which hosted runners cannot answer.
                "-A",
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
    # Do not synthesize vendor first-run JSON here. Vivaldi verifies signed
    # search-engine data and crashes after deleting an unsigned `{}` stub.


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
    remote_debugging_port: int = 0,
    platform: str | None = None,
    has_xvfb: bool | None = None,
) -> list[str]:
    platform = platform or sys.platform
    has_xvfb = shutil.which("xvfb-run") is not None if has_xvfb is None else has_xvfb
    cmd = [
        exe,
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--disable-default-apps",
        f"--user-data-dir={user_data}",
        f"--remote-debugging-port={remote_debugging_port}",
        url,
    ]
    if platform.startswith("linux"):
        cmd.insert(-2, "--password-store=gnome-libsecret")
        if "microsoft-edge" in Path(exe).name:
            # The image's Edge launcher can remain on its first-run UI under
            # Xvfb without ever servicing the startup URL or DevTools socket.
            cmd.insert(-2, "--headless=new")
        if has_xvfb:
            cmd = ["xvfb-run", "-a", *cmd]
    elif platform == "darwin":
        # Chromium's test keychain returns the same mock_password planted above,
        # avoiding GUI keychain ACL prompts while retaining real v10 encryption.
        cmd.insert(-2, "--use-mock-keychain")
    elif platform == "win32":
        # Hosted Windows runners execute as a service without an interactive
        # desktop. Native browsers need their own modern headless mode there.
        cmd.insert(-2, "--headless=new")
    return cmd


def pick_devtools_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_devtools_or_cookie(
    proc: subprocess.Popen[bytes] | subprocess.Popen[str],
    port: int,
    user_data: Path,
    timeout: float = 45,
) -> bool:
    """Return True for CDP, or False when startup navigation seeded directly."""

    endpoint = f"http://127.0.0.1:{port}/json/version"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urlopen(endpoint, timeout=2) as response:
                payload = json.load(response)
            if payload.get("webSocketDebuggerUrl"):
                return True
        except (OSError, ValueError):
            pass
        # Edge on Linux and Yandex on macOS can honor the startup URL while
        # leaving their advertised debugging endpoint unreachable. The real
        # database is the artifact under test, so a persisted cookie is a
        # stronger success signal than a vendor-specific CDP handshake.
        if cookies_db_has_name(user_data):
            return False
        status = proc.poll()
        if status not in (None, 0):
            raise SystemExit(
                f"native chromium exited {status} before exposing {endpoint}"
            )
        time.sleep(0.25)
    status = proc.poll()
    raise SystemExit(
        f"native chromium did not expose {endpoint} within {timeout}s "
        f"(launcher status: {status})"
    )


def navigate_chromium_cdp(port: int, url: str) -> None:
    subprocess.run(
        [
            "node",
            str(ROOT / "tests/e2e/navigate_chromium_cdp.mjs"),
            str(port),
            url,
        ],
        check=True,
        cwd=str(ROOT / "tests/e2e"),
        timeout=45,
    )


def seed_chromium_native(exe: str, user_data: Path, url: str) -> None:
    devtools_port = pick_devtools_port()
    cmd = chromium_native_command(
        exe, user_data, url, remote_debugging_port=devtools_port
    )
    print("+", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, cwd=str(ROOT))
    saw_cookie = False
    try:
        has_devtools = wait_for_devtools_or_cookie(proc, devtools_port, user_data)
        if has_devtools:
            navigate_chromium_cdp(devtools_port, url)
        deadline = time.time() + 30
        while time.time() < deadline:
            if cookies_db_has_name(user_data):
                saw_cookie = True
                time.sleep(1)
                break
            time.sleep(0.5)
        if not saw_cookie:
            raise SystemExit(
                "native Chromium navigation requested rookie_ci but the "
                "profile did not persist it"
            )
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


def esent_copy_command(source: Path, destination: Path) -> list[str]:
    return ["esentutl.exe", "/y", str(source), f"/d{destination}", "/o"]


def snapshot_internet_explorer_store(cookie_file: Path) -> Path:
    """Copy the real ESE store out of the Windows WebCache share lock."""

    destination = (
        Path(tempfile.gettempdir()) / f"rookie-ie-WebCacheV01-{time.time_ns()}.dat"
    )
    completed = subprocess.run(
        esent_copy_command(cookie_file, destination),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or not destination.is_file():
        details = completed.stderr.strip() or completed.stdout.strip() or "<no output>"
        raise SystemExit(f"esentutl could not snapshot IE WebCache: {details}")
    return destination


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

    server, port, _log_path, request_log = start_cookie_server()
    try:
        plant_keychain()
        url = f"http://127.0.0.1:{port}/set"
        if engine == "gecko":
            seed_gecko(exe, user_data, url)
            assert_gecko(user_data)
        elif engine == "safari":
            before = file_snapshot(engine)
            cookie_file = seed_safari_native(exe, url, before, request_log)
            os.environ["ROOKIE_E2E_COOKIE_DB"] = str(cookie_file)
            print(f"native cookie store: {cookie_file}", flush=True)
            assert_native(cookie_file, browser)
        elif engine == "internet_explorer":
            before = file_snapshot(engine)
            cookie_file = seed_with_startup_retry(engine, exe, url, before)
            stop_browser(engine)
            cookie_file = snapshot_internet_explorer_store(cookie_file)
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
