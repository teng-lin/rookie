#!/usr/bin/env python3
"""Seed an installed claimed browser and assert its exact portable corpus.

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
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

from browser_coverage_contract import assert_observed_depth, coverage_row, load_coverage
from hosted_cookie_corpus import corpus_seed_url, write_hosted_manifest
from run_exact_corpus_e2e import (
    configure_isolated_keychain,
    digest_fields,
    normalized_path_bytes,
)
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


def canonical_root_digest_path(root: Path, platform: str) -> Path:
    """Mirror Rust's Windows canonicalize spelling before hashing an ID."""

    value = str(root)
    if platform == "windows" and not value.startswith("\\\\?\\"):
        return Path("\\\\?\\" + value)
    return root


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
        normalized_path_bytes(canonical_root_digest_path(root, platform)),
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
    *,
    tls: bool = False,
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
            with socket.create_connection(("127.0.0.1", port), timeout=0.5) as raw:
                if tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(raw, server_hostname="127.0.0.1"):
                        return
                return
        except OSError:
            time.sleep(0.25)
    logs = (
        log_path.read_text(encoding="utf-8", errors="replace")
        if log_path.is_file()
        else ""
    )
    raise SystemExit(
        f"cookie server did not become ready at "
        f"{'https' if tls else 'http'}://127.0.0.1:{port}/\n{logs}"
    )


def start_cookie_server(
    *, tls_cert: Path | None = None, tls_key: Path | None = None
) -> tuple[subprocess.Popen[str], int, Path, Path]:
    if (tls_cert is None) != (tls_key is None):
        raise SystemExit("cookie server TLS requires both certificate and private key")
    port = pick_cookie_port()
    env = os.environ.copy()
    env["ROOKIE_E2E_COOKIE_PORT"] = str(port)
    log_path = Path(tempfile.gettempdir()) / f"rookie-cookie-server-{port}.log"
    request_log = Path(tempfile.gettempdir()) / f"rookie-cookie-requests-{port}.log"
    request_log.write_text("", encoding="utf-8")
    env["ROOKIE_E2E_REQUEST_LOG"] = str(request_log)
    if tls_cert is not None and tls_key is not None:
        env["ROOKIE_E2E_COOKIE_SCHEME"] = "https"
        env["ROOKIE_E2E_COOKIE_TLS_CERT"] = str(tls_cert)
        env["ROOKIE_E2E_COOKIE_TLS_KEY"] = str(tls_key)
    with log_path.open("w", encoding="utf-8") as log_handle:
        proc = subprocess.Popen(
            [sys.executable, "-u", str(ROOT / "tests/e2e/cookie_server.py")],
            cwd=str(ROOT),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
    wait_for_server(port, proc, log_path, tls=tls_cert is not None)
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


def wait_for_request(
    request_log: Path,
    path: str,
    timeout: float = 30,
    *,
    query_contains: str | None = None,
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests = request_log.read_text(encoding="utf-8").splitlines()
        except OSError:
            requests = []
        if any(
            urlsplit(request).path == path
            and (query_contains is None or query_contains in urlsplit(request).query)
            for request in requests
        ):
            return
        time.sleep(0.25)
    raise SystemExit(f"browser never requested {path}; observed requests: {requests!r}")


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
        parsed_url = urlsplit(url)
        if parsed_url.path == "/corpus/run":
            # Four origin/phase responses complete the portable redirect chain.
            wait_for_request(
                request_log,
                "/corpus/run",
                query_contains="step=3",
            )
        else:
            wait_for_request(request_log, parsed_url.path)
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


def require_disposable_safari_host(scratch_profile: Path) -> None:
    """Refuse to open Safari's normal store outside a fresh hosted CI account."""

    if (
        os.environ.get("CI", "").lower() != "true"
        or os.environ.get("GITHUB_ACTIONS", "").lower() != "true"
        or os.environ.get("ROOKIE_E2E_RUNNER_ENVIRONMENT", "").lower()
        != "github-hosted"
    ):
        raise SystemExit(
            "Safari live extraction is restricted to a fresh GitHub-hosted CI "
            "account; never run it against a local default Safari profile"
        )
    runner_temp_raw = os.environ.get("RUNNER_TEMP")
    if not runner_temp_raw:
        raise SystemExit("RUNNER_TEMP must identify the disposable Safari job root")
    runner_temp = Path(runner_temp_raw).resolve(strict=True)
    try:
        scratch_profile.resolve().relative_to(runner_temp)
    except ValueError as error:
        raise SystemExit(
            f"Safari scratch profile {scratch_profile} is outside RUNNER_TEMP"
        ) from error


def generate_trusted_safari_certificate(scratch_profile: Path) -> tuple[Path, Path]:
    """Create and trust a short-lived localhost certificate on a hosted VM."""

    if sys.platform != "darwin":
        raise SystemExit("Safari HTTPS certificate setup requires macOS")
    require_disposable_safari_host(scratch_profile)
    openssl = shutil.which("openssl")
    if openssl is None:
        raise SystemExit("Safari HTTPS requires openssl on PATH")
    tls_dir = scratch_profile / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    authority = tls_dir / "rookie-local-ca.pem"
    authority_key = tls_dir / "rookie-local-ca-key.pem"
    certificate = tls_dir / "rookie-localhost.pem"
    private_key = tls_dir / "rookie-localhost-key.pem"
    request = tls_dir / "rookie-localhost.csr"
    extensions = tls_dir / "rookie-localhost.ext"
    extensions.write_text(
        "[server]\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    try:
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Rookie E2E Local CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                str(authority_key),
                "-out",
                str(authority),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        subprocess.run(
            [
                openssl,
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
                "-keyout",
                str(private_key),
                "-out",
                str(request),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        subprocess.run(
            [
                openssl,
                "x509",
                "-req",
                "-in",
                str(request),
                "-CA",
                str(authority),
                "-CAkey",
                str(authority_key),
                "-CAcreateserial",
                "-days",
                "1",
                "-sha256",
                "-extfile",
                str(extensions),
                "-extensions",
                "server",
                "-out",
                str(certificate),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        subprocess.run(
            [
                "/usr/bin/sudo",
                "-n",
                "/usr/bin/security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustAsRoot",
                "-p",
                "ssl",
                "-s",
                "127.0.0.1",
                "-k",
                "/Library/Keychains/System.keychain",
                str(certificate),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Check the same Security.framework trust settings Safari consumes.
        # Trusting the short-lived leaf directly avoids depending on whether a
        # browser accepts an omitted locally generated intermediate/root.
        subprocess.run(
            [
                "/usr/bin/security",
                "verify-cert",
                "-c",
                str(certificate),
                "-p",
                "ssl",
                "-s",
                "127.0.0.1",
                "-k",
                "/Library/Keychains/System.keychain",
                "-L",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        details = (error.stderr or error.stdout or "").strip()
        raise SystemExit(
            "failed to prepare trusted Safari HTTPS certificate on the fresh "
            f"hosted runner: {details}"
        ) from error
    return certificate, private_key


def verify_safari_https_server(port: int) -> None:
    """Prove the hosted macOS system trust and TLS server before opening Safari."""

    try:
        subprocess.run(
            [
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "10",
                f"https://127.0.0.1:{port}/health",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        details = (error.stderr or error.stdout or "").strip()
        raise SystemExit(
            "Safari HTTPS preflight could not validate the disposable local "
            f"origin with macOS system trust: {details}"
        ) from error


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
    if os.environ.get("ROOKIE_E2E_EPHEMERAL_KEYCHAIN"):
        # The wrapper already planted the exact service/account pairs into its
        # disposable keychain.  Adding them again without an explicit keychain
        # path would target the runner's normal default keychain.
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


def chromium_automation_user_data(
    browser: str, platform: str, requested: Path, registry_root: Path
) -> Path:
    """Select a fresh browser-launch root without weakening discovery checks."""

    # Chromium 136+ products may suppress remote debugging when --user-data-dir
    # names their computed default root. Windows Yandex enforces that boundary;
    # launch it in the separately supplied disposable scratch root, then stage
    # the stopped browser output into the equally disposable registry root.
    if browser == "yandex" and platform == "windows":
        return requested
    return registry_root


def stage_chromium_discovery_profile(source: Path, target: Path) -> None:
    """Stage stopped browser cookie artifacts into an empty registry root."""

    source = source.resolve(strict=True)
    target = target.resolve()
    if source == target:
        return
    if source.is_relative_to(target) or target.is_relative_to(source):
        raise SystemExit("Chromium launch and discovery roots must not overlap")
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise SystemExit(f"Chromium discovery root was not empty: {target}")
    databases = chromium_cookie_dbs(source)
    if not databases:
        raise SystemExit(f"Chromium automation root had no cookie database: {source}")
    local_state = source / "Local State"
    if local_state.is_file():
        shutil.copy2(local_state, target / local_state.name)
    for database in databases:
        relative = database.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(database, destination)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{database}{suffix}")
            if sidecar.is_file():
                shutil.copy2(sidecar, Path(f"{destination}{suffix}"))
        for settings_name in ("Preferences", "Secure Preferences"):
            settings = database.parent.parent / settings_name
            if settings.is_file():
                shutil.copy2(settings, target / settings.relative_to(source))


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


def wait_for_chromium_cookie(
    user_data: Path, timeout: float, *, name: str = "rookie_ci"
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cookies_db_has_name(user_data, name):
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
        completion_name = (
            "rookie_decoy" if urlsplit(url).path == "/corpus/run" else "rookie_ci"
        )
        saw_cookie = wait_for_chromium_cookie(user_data, 30, name=completion_name)
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
    if not saw_cookie and not wait_for_chromium_cookie(
        user_data, 15, name=completion_name
    ):
        candidates = ", ".join(str(path) for path in chromium_cookie_dbs(user_data))
        raise SystemExit(
            f"native Chromium navigation requested {completion_name} but the profile "
            f"did not persist it (cookie databases: {candidates or '<none>'})"
        )


def wait_for_gecko_database(profile: Path, timeout: float = 30) -> None:
    database = profile / "cookies.sqlite"
    deadline = time.time() + timeout
    last_error: sqlite3.Error | None = None
    while time.time() < deadline:
        if database.is_file():
            try:
                connection = sqlite3.connect(
                    database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.2
                )
                try:
                    connection.execute("pragma table_info(moz_cookies)").fetchall()
                finally:
                    connection.close()
                return
            except sqlite3.Error as error:
                last_error = error
        time.sleep(0.25)
    raise SystemExit(
        f"Gecko cookie database did not become readable at {database}: {last_error}"
    )


def seed_gecko(exe: str, profile: Path, url: str, request_log: Path) -> None:
    profile.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "--headless", "--no-remote", "--profile", str(profile), url]
    env = os.environ.copy()
    env["MOZ_HEADLESS"] = "1"
    print("+", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env)
    try:
        parsed_url = urlsplit(url)
        wait_for_request(
            request_log,
            parsed_url.path,
            timeout=90,
            query_contains="step=3" if parsed_url.path == "/corpus/run" else None,
        )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
    wait_for_gecko_database(profile)


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
    """Keep the legacy IE canary exact until a hosted IE cell exists."""

    name = env.get("ROOKIE_E2E_COOKIE_NAME", "rookie_ci")
    value = env.get("ROOKIE_E2E_COOKIE_VALUE", "bar")
    env["ROOKIE_E2E_REQUIRED_COOKIES_JSON"] = json.dumps({name: value})
    env["ROOKIE_E2E_FORBIDDEN_COOKIES_JSON"] = "[]"
    env["ROOKIE_E2E_EXACT_COOKIE_STATE"] = "1"


def assert_chromium(user_data: Path, browser_id: str) -> None:
    env = os.environ.copy()
    env["ROOKIE_E2E_USER_DATA_DIR"] = str(user_data)
    env["ROOKIE_E2E_BROWSER_ID"] = browser_id
    env["ROOKIE_E2E_CHECK_RECOMMENDED_READ"] = "1"
    db = find_chromium_db(user_data, name="rookie_ci")
    env["ROOKIE_E2E_COOKIE_MANIFEST"] = str(
        write_hosted_manifest(
            engine="chromium",
            browser=browser_id,
            platform=current_platform(),
            profile=user_data,
            database=db,
        )
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
            "--profile",
            env["ROOKIE_E2E_EXPECTED_PROFILE_ID"],
            "--detailed",
        ],
        check=True,
        env=env,
    )


def assert_gecko(profile: Path, browser_id: str) -> None:
    env = os.environ.copy()
    env["ROOKIE_E2E_FIREFOX_PROFILE"] = str(profile)
    env["ROOKIE_E2E_BROWSER_ID"] = browser_id
    env["ROOKIE_E2E_CHECK_RECOMMENDED_READ"] = "1"
    env["ROOKIE_E2E_COOKIE_MANIFEST"] = str(
        write_hosted_manifest(
            engine="firefox",
            browser=browser_id,
            platform=current_platform(),
            profile=profile,
            database=profile / "cookies.sqlite",
        )
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
            "--profile",
            env["ROOKIE_E2E_EXPECTED_PROFILE_ID"],
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


def assert_native(cookie_file: Path, browser: str, profile: Path) -> None:
    env = os.environ.copy()
    if browser == "safari":
        env["ROOKIE_E2E_COOKIE_MANIFEST"] = str(
            write_hosted_manifest(
                engine="safari",
                browser=browser,
                platform=current_platform(),
                profile=profile,
                database=cookie_file,
            )
        )
    else:
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
    if browser == "safari":
        subprocess.run(
            [
                str(py),
                str(ROOT / "tests/e2e/assert_cli_cookie.py"),
                str(cookie_file),
                "--detailed",
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
        configure_isolated_keychain(os.environ)
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
    # Every path here is newly created below RUNNER_TEMP. Some products also
    # require the automation root to differ from their registry default; that
    # launch/store distinction is handled explicitly below.
    user_data.mkdir(parents=True, exist_ok=True)

    tls_cert = None
    tls_key = None
    if engine == "safari":
        require_disposable_safari_host(user_data)
        tls_cert, tls_key = generate_trusted_safari_certificate(user_data)

    server, port, _log_path, request_log = start_cookie_server(
        tls_cert=tls_cert, tls_key=tls_key
    )
    try:
        if engine == "safari":
            verify_safari_https_server(port)
        plant_keychain()
        url = (
            f"http://127.0.0.1:{port}/set"
            if engine == "internet_explorer"
            else corpus_seed_url(
                port, engine, scheme="https" if engine == "safari" else "http"
            )
        )
        if engine == "gecko":
            seed_gecko(exe, user_data, url, request_log)
            assert_gecko(user_data, browser)
        elif engine == "safari":
            before = file_snapshot(engine)
            cookie_file = seed_safari_native(exe, url, before, request_log)
            verify_safari_store_access(cookie_file)
            os.environ["ROOKIE_E2E_COOKIE_DB"] = str(cookie_file)
            print(f"native cookie store: {cookie_file}", flush=True)
            assert_native(cookie_file, browser, user_data)
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
            assert_native(cookie_file, browser, user_data)
        else:
            os.environ["ROOKIE_E2E_BROWSER_PATH"] = exe
            automation_user_data = chromium_automation_user_data(
                browser, platform, requested_user_data, user_data
            )
            stage_chromium_user_data(automation_user_data)
            seed_chromium_native(exe, automation_user_data, url)
            stage_chromium_discovery_profile(automation_user_data, user_data)
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
    elif engine == "safari":
        observed.update({"detailed", "exact_set"})
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
