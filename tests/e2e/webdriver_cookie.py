#!/usr/bin/env python3
"""Drive Safari/Internet Explorer without adding a Selenium client dependency.

Both hosted images already include the vendor WebDriver server. This module
speaks the small W3C WebDriver subset the cookie canary needs and retries only
driver/browser startup and navigation readiness. Extraction is never retried.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class WebDriverError(RuntimeError):
    pass


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(
    port: int,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout: float = 15,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        method=method,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        raise WebDriverError(
            f"WebDriver {method} {path} returned HTTP {error.code}: {raw}"
        ) from error
    except OSError as error:
        raise WebDriverError(f"WebDriver {method} {path} failed: {error}") from error
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        raise WebDriverError(f"WebDriver returned non-JSON data: {raw!r}") from error
    value = result.get("value")
    if isinstance(value, dict) and value.get("error"):
        raise WebDriverError(
            f"WebDriver {value.get('error')}: {value.get('message', '<no message>')}"
        )
    return result


def wait_for_driver(
    port: int, proc: subprocess.Popen[bytes], timeout: float = 30
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise WebDriverError(f"WebDriver exited with status {proc.returncode}")
        try:
            request_json(port, "GET", "/status", timeout=2)
            return
        except WebDriverError:
            time.sleep(0.25)
    raise WebDriverError("WebDriver did not become ready")


def driver_command(engine: str, driver: str, port: int) -> list[str]:
    if engine == "safari":
        return [driver, "--port", str(port)]
    if engine == "internet_explorer":
        return [driver, f"--port={port}", "--log-level=TRACE"]
    raise WebDriverError(f"unsupported native WebDriver engine {engine!r}")


def capabilities(engine: str) -> dict[str, Any]:
    if engine == "safari":
        always_match: dict[str, Any] = {"browserName": "safari"}
    elif engine == "internet_explorer":
        always_match = {
            "browserName": "internet explorer",
            "se:ieOptions": {
                "ensureCleanSession": True,
                "ignoreProtectedModeSettings": True,
                "ignoreZoomSetting": True,
                "initialBrowserUrl": "about:blank",
            },
        }
    else:
        raise WebDriverError(f"unsupported native WebDriver engine {engine!r}")
    return {"capabilities": {"alwaysMatch": always_match}}


def stop_browser(engine: str) -> None:
    if engine == "safari":
        subprocess.run(["pkill", "-x", "Safari"], check=False, capture_output=True)
        subprocess.run(
            ["pkill", "-x", "safaridriver"], check=False, capture_output=True
        )
    elif engine == "internet_explorer":
        subprocess.run(
            ["taskkill", "/F", "/IM", "iexplore.exe"],
            check=False,
            capture_output=True,
        )


def seed_once(engine: str, driver: str, url: str, log_path: Path) -> None:
    port = free_port()
    command = driver_command(engine, driver, port)
    print("+", " ".join(command), flush=True)
    with log_path.open("wb") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    session_id: str | None = None
    try:
        wait_for_driver(port, proc)
        response = request_json(
            port, "POST", "/session", capabilities(engine), timeout=60
        )
        value = response.get("value", {})
        session_id = value.get("sessionId") or response.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise WebDriverError(f"WebDriver did not return a session id: {response!r}")
        request_json(
            port,
            "POST",
            f"/session/{session_id}/url",
            {"url": url},
            timeout=60,
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                cookie_response = request_json(
                    port,
                    "GET",
                    f"/session/{session_id}/cookie/rookie_ci",
                    timeout=5,
                )
                cookie = cookie_response.get("value")
                if isinstance(cookie, dict) and cookie.get("value") == "bar":
                    return
            except WebDriverError:
                pass
            time.sleep(0.5)
        raise WebDriverError("browser never exposed rookie_ci=bar through WebDriver")
    finally:
        if session_id and proc.poll() is None:
            try:
                request_json(port, "DELETE", f"/session/{session_id}", timeout=15)
            except WebDriverError:
                pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


def seed_with_startup_retry(engine: str, driver: str, url: str) -> None:
    failures: list[str] = []
    for attempt in range(1, 3):
        stop_browser(engine)
        log_path = (
            Path(tempfile.gettempdir()) / f"rookie-{engine}-webdriver-{attempt}.log"
        )
        try:
            seed_once(engine, driver, url, log_path)
            return
        except WebDriverError as error:
            logs = (
                log_path.read_text(encoding="utf-8", errors="replace")
                if log_path.is_file()
                else "<no driver log>"
            )
            failures.append(f"attempt {attempt}: {error}\n{logs}")
            print(
                f"native WebDriver startup attempt {attempt} failed: {error}",
                flush=True,
            )
    raise WebDriverError("native WebDriver seed failed twice:\n" + "\n".join(failures))


def candidate_cookie_files(engine: str) -> list[Path]:
    if engine == "safari":
        library = Path.home() / "Library"
        candidates = [
            library
            / "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
            library / "Cookies/Cookies.binarycookies",
        ]
        store = (
            library / "Containers/com.apple.Safari/Data/Library/WebKit/WebsiteDataStore"
        )
        try:
            candidates.extend(store.glob("*/WebsiteData/Cookies/Cookies.binarycookies"))
        except OSError:
            pass
        return candidates
    if engine == "internet_explorer":
        candidates = []
        for variable in ("APPDATA", "LOCALAPPDATA"):
            root = os.environ.get(variable)
            if root:
                candidates.append(
                    Path(root) / "Microsoft/Windows/WebCache/WebCacheV01.dat"
                )
        return candidates
    raise WebDriverError(f"unsupported native cookie engine {engine!r}")


def file_snapshot(engine: str) -> dict[Path, tuple[int, int]]:
    snapshot: dict[Path, tuple[int, int]] = {}
    for path in candidate_cookie_files(engine):
        try:
            stat = path.stat()
        except OSError:
            continue
        snapshot[path] = (stat.st_mtime_ns, stat.st_size)
    return snapshot


def wait_for_changed_cookie_file(
    engine: str,
    before: dict[Path, tuple[int, int]],
    timeout: float = 60,
) -> Path:
    deadline = time.time() + timeout
    last_seen: list[Path] = []
    while time.time() < deadline:
        changed: list[tuple[int, Path]] = []
        last_seen = []
        for path in candidate_cookie_files(engine):
            try:
                stat = path.stat()
            except OSError:
                continue
            last_seen.append(path)
            state = (stat.st_mtime_ns, stat.st_size)
            if stat.st_size > 0 and before.get(path) != state:
                changed.append((stat.st_mtime_ns, path))
        if changed:
            return max(changed)[1]
        time.sleep(0.5)
    rendered = ", ".join(str(path) for path in last_seen) or "<none>"
    raise WebDriverError(
        f"{engine} did not create or update a cookie store; visible candidates: {rendered}"
    )


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: webdriver_cookie.py ENGINE DRIVER URL")
    seed_with_startup_retry(sys.argv[1], sys.argv[2], sys.argv[3])
