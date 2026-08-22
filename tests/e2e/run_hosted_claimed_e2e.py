#!/usr/bin/env python3
"""Seed an installed claimed browser and extract rookie_ci=bar.

Installed Chromium-family browsers are launched through their native CLI,
using foreground Xvfb on most Linux images and modern headless mode where the
runner has no interactive desktop or a first-run UI blocks startup. A published
DevTools port seeds the persistent profile without relying on Playwright's
arbitrary-executable launch contract. Gecko forks use their native CLI too;
Safari launches the normal system application, and IE uses a pinned 32-bit
IEDriver server in Edge IE mode.
"""

from __future__ import annotations

import ctypes
from datetime import datetime, timedelta, timezone
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

from browser_coverage_contract import assert_observed_depth, coverage_row, load_coverage
from run_exact_corpus_e2e import digest_fields, normalized_path_bytes
from webdriver_cookie import (
    WebDriverError,
    file_snapshot,
    seed_with_startup_retry,
    stop_browser,
    wait_for_changed_cookie_file,
)


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "rookie-rs/browser_registry.json"


def current_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def isolated_discovery_environment(root: Path) -> dict[str, str]:
    """Return registry environment variables that cannot reach a user profile."""

    home = root / "home"
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "LOCALAPPDATA": str(home / "AppData/Local"),
        "APPDATA": str(home / "AppData/Roaming"),
    }


def registry_browser(platform: str, browser: str) -> dict:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    matches = [
        item
        for item in registry["platforms"][platform]
        if item["canonical_id"] == browser
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one registry entry for {platform}/{browser}, got {len(matches)}"
        )
    return matches[0]


def resolve_fixture_root(template: str, environment: dict[str, str]) -> Path:
    replacements = {
        "{home}": environment["HOME"],
        "{config_home}": environment["XDG_CONFIG_HOME"],
        "{xdg_config_home}": environment["XDG_CONFIG_HOME"],
        "{local_app_data}": environment["LOCALAPPDATA"],
        "{roaming_app_data}": environment["APPDATA"],
    }
    value = template
    for placeholder, replacement in replacements.items():
        value = value.replace(placeholder, replacement)
    # Some packaged Windows roots contain a package-family glob.  Hosted
    # cells currently avoid those products, but resolving it keeps this helper
    # deterministic and makes its unit contract complete.
    value = value.replace("*", "rookie-fixture")
    if "{" in value or "}" in value:
        raise SystemExit(f"unresolved registry root template {template!r}")
    return Path(value)


def prepare_discovered_profile(
    sandbox: Path, platform: str, browser: str, engine: str
) -> tuple[Path, dict[str, str]]:
    """Choose a real registry root below an isolated temporary home."""

    environment = isolated_discovery_environment(sandbox)
    entry = registry_browser(platform, browser)
    roots = sorted(entry["roots"], key=lambda root: root["priority"])
    if not roots:
        raise SystemExit(f"registry browser {browser!r} has no discovery roots")
    root = resolve_fixture_root(roots[0]["template"], environment)
    if engine == "gecko":
        profile = root / "Profiles/rookie-e2e"
        profile.mkdir(parents=True, exist_ok=True)
        root.mkdir(parents=True, exist_ok=True)
        (root / "profiles.ini").write_text(
            "[Profile0]\nName=rookie-e2e\nIsRelative=1\n"
            "Path=Profiles/rookie-e2e\nDefault=1\n",
            encoding="utf-8",
        )
        return profile, environment
    root.mkdir(parents=True, exist_ok=True)
    return root, environment


def independently_expected_profile_id(
    platform: str,
    browser: str,
    engine: str,
    profile: Path,
    environment: dict[str, str],
) -> str:
    entry = registry_browser(platform, browser)
    root_spec = min(entry["roots"], key=lambda root: root["priority"])
    root = resolve_fixture_root(root_spec["template"], environment).resolve(strict=True)
    expected_profile = (
        root / "Profiles/rookie-e2e" if engine == "gecko" else root
    ).resolve(strict=True)
    if profile.resolve(strict=True) != expected_profile:
        raise SystemExit(
            f"hosted discovery profile was not at its registry root: "
            f"{profile} != {expected_profile}"
        )
    installation_id = digest_fields(
        b"rookie-install-v1",
        browser.encode(),
        root_spec["root_id"].encode(),
        root_spec["channel"].encode(),
        normalized_path_bytes(root),
    )
    locator = Path("Profiles/rookie-e2e") if engine == "gecko" else Path("Default")
    return digest_fields(
        b"rookie-profile-v1",
        installation_id.encode(),
        b"relative",
        normalized_path_bytes(locator),
    )


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


def verify_safari_store_access(cookie_file: Path) -> None:
    """Fail clearly if the runner image no longer grants Safari container access."""

    try:
        with cookie_file.open("rb") as source:
            signature = source.read(4)
    except PermissionError as error:
        raise SystemExit(
            "macOS TCC denied Safari cookie access; the runner image must "
            "preapprove kTCCServiceSystemPolicyAllFiles for the job shell"
        ) from error
    if signature != b"cook":
        raise SystemExit(f"Safari cookie store has an invalid signature: {signature!r}")
    print("Safari cookie store readable through runner Full Disk Access", flush=True)


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


def chromium_cookie_dbs(user_data: Path) -> list[Path]:
    preferred = [
        user_data / "Default/Network/Cookies",
        user_data / "Default/Cookies",
    ]
    discovered = sorted(user_data.glob("*/Network/Cookies"))
    discovered.extend(sorted(user_data.glob("*/Cookies")))
    candidates = []
    for candidate in [*preferred, *discovered]:
        if candidate.is_file() and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def cookie_db_has_name(db: Path, name: str = "rookie_ci") -> bool:
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


def cookies_db_has_name(user_data: Path, name: str = "rookie_ci") -> bool:
    return any(cookie_db_has_name(db, name) for db in chromium_cookie_dbs(user_data))


def wait_for_chromium_cookie(user_data: Path, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cookies_db_has_name(user_data):
            return True
        time.sleep(0.5)
    return False


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
    ]
    if platform.startswith("linux"):
        cmd.append("--password-store=gnome-libsecret")
        if "microsoft-edge" in Path(exe).name:
            # The image's Edge launcher can remain on its first-run UI under
            # Xvfb without ever servicing the startup URL or DevTools socket.
            cmd.append("--headless=new")
    elif platform == "darwin":
        # Chromium's test keychain returns the same mock_password planted above,
        # avoiding GUI keychain ACL prompts while retaining real v10 encryption.
        cmd.append("--use-mock-keychain")
    elif platform == "win32":
        # Hosted Windows runners execute as a service without an interactive
        # desktop. Native browsers need their own modern headless mode there.
        cmd.append("--headless=new")
    cmd.extend((f"--remote-debugging-port={remote_debugging_port}", url))
    if platform.startswith("linux") and has_xvfb:
        cmd = ["xvfb-run", "-a", *cmd]
    return cmd


def pick_devtools_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def chromium_startup_timeout(exe: str, *, platform: str | None = None) -> float:
    """Allow Edge's Linux wrapper enough time to finish first-run startup."""

    platform = platform or sys.platform
    if platform.startswith("linux") and "microsoft-edge" in Path(exe).name:
        return 90
    return 45


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
        has_devtools = wait_for_devtools_or_cookie(
            proc,
            devtools_port,
            user_data,
            timeout=chromium_startup_timeout(exe),
        )
        if has_devtools:
            navigate_chromium_cdp(devtools_port, url)
        saw_cookie = wait_for_chromium_cookie(user_data, 30)
        if saw_cookie:
            time.sleep(1)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    # Windows launchers can outlive the browser process addressed by
    # Browser.close. Do not reject a delayed cookie checkpoint until the
    # launcher has also stopped and released the SQLite store.
    if not saw_cookie and not wait_for_chromium_cookie(user_data, 15):
        candidates = ", ".join(str(path) for path in chromium_cookie_dbs(user_data))
        raise SystemExit(
            "native Chromium navigation requested rookie_ci but the profile "
            f"did not persist it (cookie databases: {candidates or '<none>'})"
        )


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


def find_chromium_db(user_data: Path, *, name: str | None = None) -> Path:
    candidates = chromium_cookie_dbs(user_data)
    if name:
        for candidate in candidates:
            if cookie_db_has_name(candidate, name):
                return candidate
    if candidates:
        return candidates[0]
    raise SystemExit(f"no Chromium Cookies db under {user_data}")


def require_exact_single_cookie(env: dict[str, str]) -> None:
    """Make the broad hosted lane reject every unseeded or duplicate row."""

    name = env.get("ROOKIE_E2E_COOKIE_NAME", "rookie_ci")
    value = env.get("ROOKIE_E2E_COOKIE_VALUE", "bar")
    env["ROOKIE_E2E_REQUIRED_COOKIES_JSON"] = json.dumps({name: value})
    env["ROOKIE_E2E_FORBIDDEN_COOKIES_JSON"] = "[]"
    env["ROOKIE_E2E_EXACT_COOKIE_STATE"] = "1"


def write_live_smoke_manifest(engine: str, profile: Path, database: Path) -> Path:
    """Build a one-row structural oracle from the seed contract plus raw metadata."""

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        table = "cookies" if engine == "chromium" else "moz_cookies"
        columns = {
            str(row[1]) for row in connection.execute(f"pragma table_info({table})")
        }
        rows = connection.execute(f"select * from {table}").fetchall()
    finally:
        connection.close()
    if len(rows) != 1 or rows[0]["name"] != "rookie_ci":
        names = [row["name"] for row in rows if "name" in row.keys()]
        raise SystemExit(
            f"fresh {engine} hosted profile must contain exactly rookie_ci; "
            f"observed {len(rows)} rows: {names}"
        )
    row = rows[0]

    def optional(name: str, default: object = None) -> object:
        return row[name] if name in columns else default

    if engine == "chromium":
        raw_expiry = int(row["expires_utc"])
        expires = (
            (raw_expiry - 11_644_473_600_000_000) // 1_000_000
            if raw_expiry > 11_644_473_600_000_000
            else None
        )
        flat = {
            "domain": str(row["host_key"]),
            "path": str(row["path"]),
            "secure": bool(row["is_secure"]),
            "expires": expires,
            "name": "rookie_ci",
            "value": "bar",
            "http_only": bool(row["is_httponly"]),
            "same_site": int(row["samesite"]),
        }
        top_key = optional("top_frame_site_key")
        context = {
            "top_frame_site_key": None if top_key in (None, "") else str(top_key),
            "has_cross_site_ancestor": (
                bool(optional("has_cross_site_ancestor"))
                if "has_cross_site_ancestor" in columns
                else None
            ),
            "source_scheme": (
                int(optional("source_scheme")) if "source_scheme" in columns else None
            ),
            "source_port": (
                int(optional("source_port")) if "source_port" in columns else None
            ),
            "is_persistent": (
                bool(optional("is_persistent")) if "is_persistent" in columns else None
            ),
            "origin_attributes": None,
            "user_context_id": None,
            "partition_key": None,
            "private_browsing_id": None,
        }
        manifest_path = profile / "rookie-e2e-cookie-manifest.json"
    else:
        flat = {
            "domain": str(row["host"]),
            "path": str(row["path"]),
            "secure": bool(row["isSecure"]),
            "expires": int(row["expiry"]),
            "name": "rookie_ci",
            "value": "bar",
            "http_only": bool(row["isHttpOnly"]),
            "same_site": int(row["sameSite"]),
        }
        origin_attributes = str(optional("originAttributes", "") or "")
        context = {
            "top_frame_site_key": None,
            "has_cross_site_ancestor": None,
            "source_scheme": None,
            "source_port": None,
            "is_persistent": None,
            "origin_attributes": origin_attributes,
            "user_context_id": None,
            "partition_key": None,
            "private_browsing_id": None,
        }
        manifest_path = profile / "rookie-e2e-cookie-manifest.json"
    manifest = {
        "schema_version": 1,
        "tiers": ["hosted_smoke"],
        "identities": {
            "filtered_flat": ["domain", "path", "name"],
            "unfiltered_flat": ["domain", "path", "name"],
            "detailed": [
                "cookie.domain",
                "cookie.path",
                "cookie.name",
                "context.top_frame_site_key",
                "context.origin_attributes",
            ],
        },
        "expected": {
            "filtered_flat": [flat],
            "unfiltered_flat": [flat],
            "detailed": [{"cookie": flat, "context": context}],
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest_path


def assert_chromium(user_data: Path, browser_id: str) -> None:
    env = os.environ.copy()
    require_exact_single_cookie(env)
    env["ROOKIE_E2E_USER_DATA_DIR"] = str(user_data)
    env["ROOKIE_E2E_BROWSER_ID"] = browser_id
    env["ROOKIE_E2E_CHECK_RECOMMENDED_READ"] = "1"
    db = find_chromium_db(user_data, name="rookie_ci")
    env["ROOKIE_E2E_COOKIE_MANIFEST"] = str(
        write_live_smoke_manifest("chromium", user_data, db)
    )
    env["ROOKIE_E2E_COOKIE_DB"] = str(db)
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
    cli = [str(py), str(ROOT / "tests/e2e/assert_cli_cookie.py"), str(db)]
    if sys.platform == "win32":
        cli.extend(["--local-state-path", str(user_data / "Local State")])
    else:
        cli.extend(["--browser-id", browser_id])
    subprocess.run(cli, check=True, env=env)
    subprocess.run([*cli, "--detailed"], check=True, env=env)
    subprocess.run(
        [
            str(py),
            str(ROOT / "tests/e2e/assert_cli_cookie.py"),
            "--browser",
            browser_id,
            "--detailed",
        ],
        check=True,
        env=env,
    )


def assert_gecko(profile: Path, browser_id: str) -> None:
    env = os.environ.copy()
    require_exact_single_cookie(env)
    env["ROOKIE_E2E_FIREFOX_PROFILE"] = str(profile)
    env["ROOKIE_E2E_BROWSER_ID"] = browser_id
    env["ROOKIE_E2E_CHECK_RECOMMENDED_READ"] = "1"
    env["ROOKIE_E2E_COOKIE_MANIFEST"] = str(
        write_live_smoke_manifest("gecko", profile, profile / "cookies.sqlite")
    )
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
        [
            str(py),
            str(ROOT / "tests/e2e/assert_cli_cookie.py"),
            str(profile / "cookies.sqlite"),
            "--detailed",
        ],
        check=True,
        env=env,
    )
    subprocess.run(
        [
            str(py),
            str(ROOT / "tests/e2e/assert_cli_cookie.py"),
            "--browser",
            browser_id,
            "--detailed",
        ],
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
    require_exact_single_cookie(env)
    env["ROOKIE_E2E_EXPECT_NATIVE_FIELDS"] = "1"
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


def esent_recovery_command(snapshot_dir: Path) -> list[str]:
    return [
        "esentutl.exe",
        "/r",
        "V01",
        f"/l{snapshot_dir}",
        f"/s{snapshot_dir}",
        f"/d{snapshot_dir}",
        "/o",
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _RmUniqueProcess(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32), ("started", _FileTime)]


class _RmProcessInfo(ctypes.Structure):
    _fields_ = [
        ("process", _RmUniqueProcess),
        ("app_name", ctypes.c_wchar * 256),
        ("service_name", ctypes.c_wchar * 64),
        ("application_type", ctypes.c_uint32),
        ("app_status", ctypes.c_uint32),
        ("terminal_session_id", ctypes.c_uint32),
        ("restartable", ctypes.c_int),
    ]


def locking_process_ids(path: Path) -> list[int]:
    """Return only processes holding this WebCache file via Restart Manager."""

    if sys.platform != "win32":
        raise SystemExit("Restart Manager lock discovery requires Windows")
    restart_manager = ctypes.WinDLL("rstrtmgr")  # type: ignore[attr-defined]
    start_session = restart_manager.RmStartSession
    register_resources = restart_manager.RmRegisterResources
    get_list = restart_manager.RmGetList
    end_session = restart_manager.RmEndSession
    start_session.argtypes = [
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.c_wchar_p,
    ]
    register_resources.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.c_uint32,
        ctypes.POINTER(_RmUniqueProcess),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    get_list.argtypes = [
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(_RmProcessInfo),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    end_session.argtypes = [ctypes.c_uint32]
    start_session.restype = register_resources.restype = ctypes.c_uint32
    get_list.restype = end_session.restype = ctypes.c_uint32

    session = ctypes.c_uint32()
    session_key = ctypes.create_unicode_buffer(33)
    result = start_session(ctypes.byref(session), 0, session_key)
    if result != 0:
        raise SystemExit(f"Restart Manager could not start a session: {result}")
    try:
        resources = (ctypes.c_wchar_p * 1)(str(path))
        result = register_resources(session, 1, resources, 0, None, 0, None)
        if result != 0:
            raise SystemExit(f"Restart Manager could not register WebCache: {result}")

        needed = ctypes.c_uint32()
        count = ctypes.c_uint32()
        reboot_reasons = ctypes.c_uint32()
        result = get_list(
            session,
            ctypes.byref(needed),
            ctypes.byref(count),
            None,
            ctypes.byref(reboot_reasons),
        )
        if result == 0:
            return []
        if result != 234:  # ERROR_MORE_DATA
            raise SystemExit(f"Restart Manager could not inspect WebCache: {result}")

        for _attempt in range(3):
            count.value = needed.value
            processes = (_RmProcessInfo * needed.value)()
            result = get_list(
                session,
                ctypes.byref(needed),
                ctypes.byref(count),
                processes,
                ctypes.byref(reboot_reasons),
            )
            if result == 0:
                return sorted(
                    {
                        int(processes[index].process.pid)
                        for index in range(count.value)
                        if processes[index].process.pid != os.getpid()
                    }
                )
            if result != 234:
                break
        raise SystemExit(
            f"Restart Manager could not enumerate WebCache locks: {result}"
        )
    finally:
        end_session(session)


def webcache_host_commands(process_ids: list[int]) -> list[list[str]]:
    return [
        ["taskkill", "/F", "/PID", str(process_id)]
        for process_id in sorted(set(process_ids))
        if process_id > 0
    ]


def release_webcache_locks(cookie_file: Path) -> None:
    # The hosted runner is disposable, but taskhostw and dllhost are generic
    # system hosts. Restart Manager scopes termination to the exact processes
    # that own this IE session's WebCache file.
    for _attempt in range(3):
        process_ids = locking_process_ids(cookie_file)
        if not process_ids:
            return
        for command in webcache_host_commands(process_ids):
            subprocess.run(command, check=False, capture_output=True, timeout=15)
        time.sleep(1)
    remaining = locking_process_ids(cookie_file)
    if remaining:
        raise SystemExit(f"WebCache remains locked by process IDs: {remaining}")


def _esent_details(completed: subprocess.CompletedProcess[str]) -> str:
    return completed.stderr.strip() or completed.stdout.strip() or "<no output>"


def wininet_cookie_data(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    expires = (now + timedelta(hours=1)).strftime("%a, %d-%b-%Y %H:%M:%S GMT")
    return f"bar; expires={expires}; path=/"


def seed_internet_explorer_wininet(url: str) -> None:
    """Persist the canary through IE's native WinINet cookie database API."""

    if sys.platform != "win32":
        raise SystemExit("WinINet cookie seeding requires Windows")
    wininet = ctypes.WinDLL("wininet")  # type: ignore[attr-defined]
    set_cookie = wininet.InternetSetCookieExW
    set_cookie.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_size_t,
    ]
    set_cookie.restype = ctypes.c_uint32
    state = set_cookie(url, "rookie_ci", wininet_cookie_data(), 0, 0)
    # INTERNET_COOKIE_STATE_ACCEPT through INTERNET_COOKIE_STATE_DOWNGRADE all
    # represent stored cookies; UNKNOWN and REJECT do not.
    if state not in (1, 2, 3, 4):
        raise SystemExit(f"WinINet rejected the persistent IE canary (state {state})")
    print("native WinINet persistent cookie seeded", flush=True)


def snapshot_internet_explorer_store(cookie_file: Path) -> Path:
    """Copy and recover the real IE ESE store plus its transaction logs."""

    release_webcache_locks(cookie_file)
    snapshot_dir = Path(tempfile.mkdtemp(prefix="rookie-ie-WebCache-"))
    destination = snapshot_dir / cookie_file.name
    for source in cookie_file.parent.glob("V01*"):
        if source.is_file():
            shutil.copy2(source, snapshot_dir / source.name)
    try:
        completed = subprocess.run(
            esent_copy_command(cookie_file, destination),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        details = (error.stderr or error.stdout or "<no output>").strip()
        raise SystemExit(
            f"esentutl timed out while copying IE WebCache: {details}"
        ) from error
    if completed.returncode != 0 or not destination.is_file():
        raise SystemExit(
            f"esentutl could not snapshot IE WebCache: {_esent_details(completed)}"
        )

    try:
        recovered = subprocess.run(
            esent_recovery_command(snapshot_dir),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        details = (error.stderr or error.stdout or "<no output>").strip()
        raise SystemExit(
            f"esentutl timed out while recovering IE WebCache: {details}"
        ) from error
    if recovered.returncode != 0:
        raise SystemExit(
            f"esentutl could not recover IE WebCache: {_esent_details(recovered)}"
        )
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
    requested_user_data = Path(
        os.environ.get("ROOKIE_E2E_USER_DATA_DIR", workspace / ".rookie-ci" / browser)
    )
    platform = current_platform()
    coverage = load_coverage()
    row = coverage_row(platform, browser, coverage)
    if row["lane"] != "nightly_hosted" or row["engine"] != engine:
        raise SystemExit(
            f"coverage contract disagrees with hosted job: {platform}/{browser}/{engine}"
        )
    if engine in {"chromium", "gecko"}:
        sandbox = requested_user_data.parent / f"{browser}-registry-sandbox"
        user_data, discovery_environment = prepare_discovered_profile(
            sandbox, platform, browser, engine
        )
        # Discovery must see only the isolated home, while cargo/rustup still
        # need their already-installed toolchains from the runner account.
        original_home = Path(os.environ.get("HOME", str(Path.home())))
        os.environ.setdefault("CARGO_HOME", str(original_home / ".cargo"))
        os.environ.setdefault("RUSTUP_HOME", str(original_home / ".rustup"))
        os.environ.update(discovery_environment)
        os.environ.pop("CHROME_CONFIG_HOME", None)
        os.environ["ROOKIE_E2E_USER_DATA_DIR"] = str(user_data)
        os.environ["ROOKIE_E2E_EXPECTED_PROFILE_ID"] = (
            independently_expected_profile_id(
                platform, browser, engine, user_data, discovery_environment
            )
        )
        print(f"isolated registry profile: {user_data}", flush=True)
    else:
        user_data = requested_user_data
    # Chromium 136+ ignores remote-debugging switches for the product's
    # default data directory. A non-default profile is therefore required for
    # browser automation, including branded forks such as Windows Yandex.
    user_data.mkdir(parents=True, exist_ok=True)

    server, port, _log_path, request_log = start_cookie_server()
    try:
        plant_keychain()
        url = f"http://127.0.0.1:{port}/set"
        if engine == "gecko":
            seed_gecko(exe, user_data, url)
            assert_gecko(user_data, browser)
        elif engine == "safari":
            before = file_snapshot(engine)
            cookie_file = seed_safari_native(exe, url, before, request_log)
            verify_safari_store_access(cookie_file)
            os.environ["ROOKIE_E2E_COOKIE_DB"] = str(cookie_file)
            print(f"native cookie store: {cookie_file}", flush=True)
            assert_native(cookie_file, browser)
        elif engine == "internet_explorer":
            before = file_snapshot(engine)
            cookie_file = seed_with_startup_retry(engine, exe, url, before)
            stop_browser(engine)
            wininet_before = file_snapshot(engine)
            seed_internet_explorer_wininet(url)
            cookie_file = wait_for_changed_cookie_file(
                engine, wininet_before, timeout=30
            )
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
    observed = {"browser_launch", "explicit_path"}
    if engine == "chromium":
        observed.update(
            {
                "registry_id",
                "detailed",
                "discovery",
                "recommended_read",
                "crypto",
                "exact_set",
            }
        )
    elif engine == "gecko":
        observed.update(
            {
                "registry_id",
                "detailed",
                "discovery",
                "recommended_read",
                "exact_set",
            }
        )
    assert_observed_depth(row, observed, coverage)
    print(f"hosted claimed e2e ok: {browser} ({engine}); depth={sorted(observed)}")
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
