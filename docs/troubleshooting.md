# Troubleshooting

Platform quirks that show up as empty results, permission errors, or password
prompts. For the recommended 0.6.0 API,
see [bindings/python/README.md](../bindings/python/README.md),
[bindings/node/README.md](../bindings/node/README.md), and
[rookie-rs/README.md](../rookie-rs/README.md).

## Password prompt

On Linux, Chromium-based browsers may prompt through Secret Service / KWallet
when the library needs a keyring password. On macOS, Chromium Keychain access
can also surface a system prompt the first time a consumer process is allowed
to read the item.

## Session cookies

Pass `include_session=True` / `includeSession: true` /
`.include_session()` / `--include-session` to `read` or `jar` when you need a
Gecko browser's declared session store (see
[ADR 0004](adr/0004-read-is-the-recommended-entry.md)). Profile selection is
independent: omit it for the legacy-first profile, or name a profile to select
that profile. Naming a profile alone does not open the session store.

Some Chromium setups historically restarted the browser to reach locked
databases. Prefer non-disruptive extraction; do not assume a process restart is
available or desirable. Session cookies may still disappear when the browser
process exits.

## macOS Safari permission denied

Recent macOS versions restrict
`~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies`.
Grant **Full Disk Access** under System Settings for the terminal or app that
runs the extraction.

## Unsupported platforms (for example Android)

Copy the cookie database off the device, then point the CLI at that file:

```console
find /data/data -type f -name Cookies
rookie-cookies from-path <Cookies path>
```

On Windows Chromium paths, select credentials explicitly with exactly one of
`--browser-id`, `--local-state-path` (a `Local State` file), or
`--plaintext-only`.

## A cross-build selects headers for the build host

If a macOS-to-Windows build mentions POSIX-only headers or functions such as
`sys/ioctl.h`, `langinfo.h`, `strerror_r`, or the two-argument Unix `mkdir`,
inspect dependency build scripts for `cfg!(windows)`, `cfg!(unix)`, or
`cfg!(target_os = ...)`. A build script runs as a host executable, so those
expressions describe the host. Target-dependent decisions must use Cargo's
`CARGO_CFG_TARGET_OS`, `CARGO_CFG_TARGET_FAMILY`, and
`CARGO_CFG_TARGET_ENV` variables.

`libesedb-sys 0.2.1` has this host/target bug. Switching from MSVC to MinGW or
adding Zig cannot correct it; Windows GNU exposes further bundled-C portability
gaps after the branch is fixed. Editing `target/.../out` or Cargo's registry
cache is also temporary because the build script re-extracts its source tree.

For the fast Windows Rust check, disable only the IE capability with the
documented `xtask check-platforms` command. A full Windows build still belongs
on native MSVC CI until a consumable upstream `libesedb-sys` fix and an MSVC
SDK/sysroot are available.

## Manually import website cookies in a browser

To push extracted cookies back into a browser console on an already-open origin.
`document.cookie` cannot create **HttpOnly** cookies; skip those or set them
through a proper client API.

```python
import json
from datetime import datetime, timezone

import rookie_cookies


def create_js_code(cookies):
    js_code = ""
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value", "")
        if not name or cookie.get("http_only"):
            continue
        parts = [f"{name}={value}", f"path={cookie.get('path') or '/'}"]
        expires = cookie.get("expires")
        if expires:
            stamped = datetime.fromtimestamp(int(expires), tz=timezone.utc)
            parts.append("expires=" + stamped.strftime("%a, %d %b %Y %H:%M:%S GMT"))
        assignment = ";".join(parts) + ";"
        js_code += f"document.cookie = {json.dumps(assignment)};\n"
    js_code += "location.reload()\n"
    return js_code


# Prefer read/jar for session import; named helpers remain for compatibility.
rows = rookie_cookies.read(
    browser="firefox", profile="default-release", include_session=True
).as_list()
# Or domain-filter the compatibility flat list:
# rows = rookie_cookies.brave(["github.com"])
print(create_js_code(rows))
```

Run the printed script only on the matching origin. Never paste real cookie
values into issues, chat logs, or shared documents.
