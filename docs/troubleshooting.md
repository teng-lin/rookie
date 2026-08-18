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

Pass `profile=` / `profile` / `.profile(...)` to `read` / `jar` when you need
session cookies (see [ADR 0004](adr/0004-read-is-the-recommended-entry.md)).
Omitting the profile keeps the legacy flat first-profile selection (persistent /
legacy-eligible cookies only).

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
rookie-cookies --path <Cookies path>
```

On Windows Chromium paths, select credentials explicitly with exactly one of
`--browser-id`, `--key-path` (a `Local State` file), or `--plaintext-only`.

## Manually import website cookies in a browser

To push extracted cookies back into a browser console on an already-open origin:

```python
import json
from datetime import datetime, timezone, timedelta

import rookie_cookies


def create_js_code(cookies):
    expires = datetime.now(timezone.utc) + timedelta(days=365)
    expires = expires.strftime("%a, %d %b %Y %H:%M:%S %Z")
    js_code = ""
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value", "")
        if name and value:
            assignment = f"{name}={value};expires={expires};"
            js_code += f"document.cookie = {json.dumps(assignment)};\n"
    js_code += "location.reload()\n"
    return js_code


# Prefer read/jar for session import; named helpers remain for compatibility.
rows = rookie_cookies.read(browser="brave", profile="Default").as_list()
# Or domain-filter the compatibility flat list:
# rows = rookie_cookies.brave(["github.com"])
print(create_js_code(rows))
```

Run the printed script only on the matching origin. Never paste real cookie
values into issues, chat logs, or shared documents.
