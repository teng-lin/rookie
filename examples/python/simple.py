"""Recommended 0.7 entry: read once, then ask a send context what to send.

`read` takes an unfiltered snapshot; `send_view` answers one browsing context
with the cookies it selects, the rendered `Cookie` header, and a count of what
was left out and why. `jar` / `as_jar` still exist, but a jar cannot represent
a CHIPS partition or a Firefox container, so they refuse an isolated snapshot
unless you pass `allow_isolation_loss=True`.

Named helpers such as chrome() remain for compatibility — see multi_import.py.
"""

import rookie_cookies as cookies

snapshot = cookies.read(browser="chrome", profile="Default")

view = snapshot.send_view(
    "https://example.com/",
    top_level_site="https://example.com",
)
print(f"selected: {len(view['cookies'])}")
print(f"header: {view['header']}")
print(f"omitted: {view['omitted']}")

for record in view["cookies"][:5]:
    cookie = record["cookie"]
    print(cookie["domain"], cookie["name"])
