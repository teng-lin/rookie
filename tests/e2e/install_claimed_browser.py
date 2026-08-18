#!/usr/bin/env python3
"""Install a claimed browser on the current OS and print its executable path.

Also emits a GitHub Actions matrix of every (OS, browser) pair we know how to
install on a hosted runner. Browsers without a silent installer stay on the
fixture lane.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def this_os() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


# Silent-install recipes that have a documented package manager or a stable
# official download URL. Obscure/commercial/deprecated products are omitted.
HOSTS: dict[str, dict] = {
    "brave": {
        "engine": "chromium",
        "keychain_service": "Brave Safe Storage",
        "keychain_account": "Brave",
        "linux": {
            "kind": "brave_apt",
            "exe": ["brave-browser", "/usr/bin/brave-browser"],
        },
        "macos": {
            "kind": "brew",
            "cask": "brave-browser",
            "exe": ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"],
        },
        "windows": {
            "kind": "winget",
            "id": "Brave.Brave",
            "exe": [
                r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
                r"%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe",
            ],
        },
    },
    "opera": {
        "engine": "chromium",
        "keychain_service": "Opera Safe Storage",
        "keychain_account": "Opera",
        "linux": {
            "kind": "opera_apt",
            "exe": ["opera", "/usr/bin/opera"],
        },
        "macos": {
            "kind": "brew",
            "cask": "opera",
            "exe": ["/Applications/Opera.app/Contents/MacOS/Opera"],
        },
        "windows": {
            "kind": "winget",
            "id": "Opera.Opera",
            "exe": [
                r"%LocalAppData%\Programs\Opera\opera.exe",
                r"%ProgramFiles%\Opera\opera.exe",
            ],
        },
    },
    "opera_gx": {
        "engine": "chromium",
        "keychain_service": "Opera Safe Storage",
        "keychain_account": "Opera",
        "macos": {
            "kind": "brew",
            "cask": "opera-gx",
            "exe": ["/Applications/Opera GX.app/Contents/MacOS/Opera GX"],
        },
        "windows": {
            "kind": "winget",
            "id": "Opera.OperaGX",
            "exe": [
                r"%LocalAppData%\Programs\Opera GX\opera.exe",
                r"%ProgramFiles%\Opera GX\opera.exe",
            ],
        },
    },
    "vivaldi": {
        "engine": "chromium",
        "keychain_service": "Vivaldi Safe Storage",
        "keychain_account": "Vivaldi",
        "linux": {
            "kind": "vivaldi_apt",
            "exe": ["vivaldi", "vivaldi-stable", "/usr/bin/vivaldi"],
        },
        "macos": {
            "kind": "brew",
            "cask": "vivaldi",
            "exe": ["/Applications/Vivaldi.app/Contents/MacOS/Vivaldi"],
        },
        "windows": {
            "kind": "winget",
            "id": "Vivaldi.Vivaldi",
            "exe": [
                r"%LocalAppData%\Vivaldi\Application\vivaldi.exe",
                r"%ProgramFiles%\Vivaldi\Application\vivaldi.exe",
            ],
        },
    },
    "yandex": {
        "engine": "chromium",
        "keychain_service": "Yandex Safe Storage",
        "keychain_account": "Yandex",
        "macos": {
            "kind": "brew",
            "cask": "yandex",
            "exe": [
                "/Applications/Yandex.app/Contents/MacOS/Yandex",
                "/Applications/Yandex Browser.app/Contents/MacOS/Yandex",
            ],
        },
        "windows": {
            "kind": "winget",
            "id": "Yandex.Browser",
            "exe": [
                r"%LocalAppData%\Yandex\YandexBrowser\Application\browser.exe",
                r"%ProgramFiles%\Yandex\YandexBrowser\Application\browser.exe",
            ],
        },
    },
    "arc": {
        "engine": "chromium",
        "keychain_service": "Arc Safe Storage",
        "keychain_account": "Arc",
        "macos": {
            "kind": "brew",
            "cask": "arc",
            "exe": ["/Applications/Arc.app/Contents/MacOS/Arc"],
        },
        "windows": {
            "kind": "winget",
            "id": "TheBrowserCompany.Arc",
            "exe": [
                r"%LocalAppData%\Programs\Arc\Arc.exe",
                r"%LocalAppData%\Arc\Application\Arc.exe",
            ],
        },
    },
    "librewolf": {
        "engine": "gecko",
        "linux": {
            "kind": "librewolf_extrepo",
            "exe": ["librewolf", "/usr/bin/librewolf"],
        },
        "macos": {
            "kind": "brew",
            "cask": "librewolf",
            "exe": ["/Applications/LibreWolf.app/Contents/MacOS/librewolf"],
        },
        "windows": {
            "kind": "winget",
            "id": "LibreWolf.LibreWolf",
            "exe": [
                r"%ProgramFiles%\LibreWolf\librewolf.exe",
                r"%LocalAppData%\LibreWolf\librewolf.exe",
            ],
        },
    },
    "zen": {
        "engine": "gecko",
        "linux": {
            "kind": "zen_tarball",
            "exe": [str(Path.home() / "rookie-e2e-zen" / "zen")],
        },
        "macos": {
            "kind": "brew",
            "cask": "zen-browser",
            "exe": ["/Applications/Zen Browser.app/Contents/MacOS/zen"],
        },
        "windows": {
            "kind": "winget",
            "id": "Zen-Team.Zen-Browser",
            "exe": [
                r"%ProgramFiles%\Zen Browser\zen.exe",
                r"%LocalAppData%\Zen Browser\zen.exe",
                r"%LocalAppData%\Programs\Zen Browser\zen.exe",
            ],
        },
    },
    "duckduckgo": {
        "engine": "chromium",
        "windows": {
            "kind": "winget",
            "id": "DuckDuckGo.DesktopBrowser",
            "exe": [
                r"%LocalAppData%\DuckDuckGo\DuckDuckGo.exe",
                r"%ProgramFiles%\DuckDuckGo\DuckDuckGo.exe",
            ],
        },
    },
}

RUNNERS = {
    "linux": "ubuntu-24.04",
    "macos": "macos-15",
    "windows": "windows-2025",
}


def find_exe(candidates: list[str]) -> str | None:
    for raw in candidates:
        path = expand(raw)
        which = shutil.which(path) if os.sep not in path and "/" not in path else None
        if which and Path(which).is_file():
            return which
        if Path(path).is_file():
            return str(Path(path).resolve())
    return None


def run(cmd: list[str], **kwargs) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, **kwargs)


def install_brave_apt() -> None:
    run(["sudo", "apt-get", "install", "-y", "curl"])
    run(
        [
            "sudo",
            "curl",
            "-fsSLo",
            "/usr/share/keyrings/brave-browser-archive-keyring.gpg",
            "https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg",
        ]
    )
    run(
        [
            "sudo",
            "curl",
            "-fsSLo",
            "/etc/apt/sources.list.d/brave-browser-release.sources",
            "https://brave-browser-apt-release.s3.brave.com/brave-browser.sources",
        ]
    )
    run(["sudo", "apt-get", "update"])
    run(["sudo", "apt-get", "install", "-y", "brave-browser"])


def install_opera_apt() -> None:
    run(["sudo", "apt-get", "install", "-y", "curl", "gnupg"])
    key = Path("/usr/share/keyrings/opera-browser.gpg")
    with urllib.request.urlopen("https://deb.opera.com/archive.key") as response:
        payload = response.read()
    subprocess.run(
        ["sudo", "gpg", "--batch", "--yes", "--dearmor", "-o", str(key)],
        input=payload,
        check=True,
    )
    line = (
        "deb [arch=amd64 signed-by=/usr/share/keyrings/opera-browser.gpg] "
        "https://deb.opera.com/opera-stable/ stable non-free\n"
    )
    subprocess.run(
        ["sudo", "tee", "/etc/apt/sources.list.d/opera-stable.list"],
        input=line.encode(),
        check=True,
    )
    run(
        [
            "sudo",
            "debconf-set-selections",
        ],
        input=b"opera-stable opera-stable/add-deb-source boolean false\n",
    )
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    run(["sudo", "apt-get", "update"])
    run(["sudo", "apt-get", "install", "-y", "opera-stable"], env=env)


def install_vivaldi_apt() -> None:
    run(["sudo", "apt-get", "install", "-y", "curl", "gnupg"])
    with urllib.request.urlopen(
        "https://repo.vivaldi.com/archive/linux_signing_key.pub"
    ) as response:
        payload = response.read()
    subprocess.run(
        [
            "sudo",
            "gpg",
            "--batch",
            "--yes",
            "--dearmor",
            "-o",
            "/usr/share/keyrings/vivaldi.gpg",
        ],
        input=payload,
        check=True,
    )
    line = (
        "deb [arch=amd64 signed-by=/usr/share/keyrings/vivaldi.gpg] "
        "https://repo.vivaldi.com/archive/deb/ stable main\n"
    )
    subprocess.run(
        ["sudo", "tee", "/etc/apt/sources.list.d/vivaldi.list"],
        input=line.encode(),
        check=True,
    )
    run(["sudo", "apt-get", "update"])
    run(["sudo", "apt-get", "install", "-y", "vivaldi-stable"])


def install_librewolf_extrepo() -> None:
    run(["sudo", "apt-get", "update"])
    run(["sudo", "apt-get", "install", "-y", "extrepo"])
    run(["sudo", "extrepo", "enable", "librewolf"])
    run(["sudo", "extrepo", "update", "librewolf"])
    run(["sudo", "apt-get", "update"])
    run(["sudo", "apt-get", "install", "-y", "librewolf"])


def install_zen_tarball() -> None:
    dest = Path.home() / "rookie-e2e-zen"
    dest.mkdir(parents=True, exist_ok=True)
    url = (
        "https://github.com/zen-browser/desktop/releases/latest/download/"
        "zen.linux-x86_64.tar.xz"
    )
    archive = Path(tempfile.gettempdir()) / "zen.linux-x86_64.tar.xz"
    urllib.request.urlretrieve(url, archive)
    run(["tar", "-xJf", str(archive), "-C", str(dest), "--strip-components=1"])
    exe = dest / "zen"
    if not exe.is_file():
        raise SystemExit(f"zen tarball did not contain {exe}")
    exe.chmod(exe.stat().st_mode | 0o111)


def install_brew(cask: str) -> None:
    env = os.environ.copy()
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    env["HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK"] = "1"
    run(["brew", "install", "--cask", cask], env=env)


def install_winget(package_id: str) -> None:
    run(
        [
            "winget",
            "install",
            "-e",
            "--id",
            package_id,
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--disable-interactivity",
            "--source",
            "winget",
        ]
    )


def install_spec(spec: dict) -> None:
    kind = spec["kind"]
    if kind == "brave_apt":
        install_brave_apt()
    elif kind == "opera_apt":
        install_opera_apt()
    elif kind == "vivaldi_apt":
        install_vivaldi_apt()
    elif kind == "librewolf_extrepo":
        install_librewolf_extrepo()
    elif kind == "zen_tarball":
        install_zen_tarball()
    elif kind == "brew":
        install_brew(spec["cask"])
    elif kind == "winget":
        install_winget(spec["id"])
    else:
        raise SystemExit(f"unknown install kind {kind!r}")


def matrix() -> list[dict[str, str]]:
    rows = []
    for browser, meta in HOSTS.items():
        for platform in RUNNERS:
            if platform not in meta:
                continue
            rows.append(
                {
                    "os": platform if platform != "linux" else "ubuntu",
                    "platform": platform,
                    "runner": RUNNERS[platform],
                    "browser": browser,
                    "engine": meta["engine"],
                }
            )
    rows.sort(key=lambda row: (row["platform"], row["browser"]))
    return rows


def write_github_env(values: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_ENV")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def install_browser(browser: str, platform: str) -> str:
    meta = HOSTS.get(browser)
    if meta is None or platform not in meta:
        raise SystemExit(
            f"no silent installer for {browser!r} on {platform}; "
            "this cell should stay on the fixture lane"
        )
    spec = meta[platform]
    exe = find_exe(spec["exe"])
    if exe is None:
        install_spec(spec)
        exe = find_exe(spec["exe"])
    if exe is None:
        raise SystemExit(f"installed {browser} on {platform} but could not find the executable")
    env = {
        "ROOKIE_E2E_BROWSER_PATH": exe,
        "ROOKIE_E2E_BROWSER_ID": browser,
        "ROOKIE_E2E_ENGINE": meta["engine"],
    }
    if meta.get("keychain_service"):
        env["ROOKIE_E2E_KEYCHAIN_SERVICE"] = meta["keychain_service"]
        env["ROOKIE_E2E_KEYCHAIN_ACCOUNT"] = meta["keychain_account"]
    write_github_env(env)
    print(json.dumps(env, indent=2))
    return exe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser")
    parser.add_argument("--platform", default=this_os())
    parser.add_argument("--print-matrix", action="store_true")
    args = parser.parse_args()
    if args.print_matrix:
        payload = json.dumps(matrix(), separators=(",", ":"))
        output = os.environ.get("GITHUB_OUTPUT")
        if output:
            with open(output, "a", encoding="utf-8") as handle:
                handle.write(f"include={payload}\n")
        print(payload)
        return 0
    if not args.browser:
        raise SystemExit("pass --browser or --print-matrix")
    install_browser(args.browser, args.platform)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
