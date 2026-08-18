"""Compatibility: named per-browser helpers (chrome, firefox, …).

Prefer examples/python/simple.py (read/jar) for new code. These helpers
stay through 0.6 and match the frozen first-profile flatten.
"""

import platform

from rookie_cookies import (
    arc,
    brave,
    chrome,
    chromium,
    edge,
    firefox,
    librewolf,
    vivaldi,
    zen,
)

browsers_fn = [arc, brave, chromium, chrome, edge, firefox, librewolf, vivaldi]

if platform.system() == "Linux":
    from rookie_cookies import cachy, opera

    browsers_fn.extend([cachy, opera])
elif platform.system() == "Windows":
    from rookie_cookies import internet_explorer, opera, opera_gx

    browsers_fn.extend([internet_explorer, opera, opera_gx])
elif platform.system() == "Darwin":
    from rookie_cookies import opera, opera_gx, safari

    browsers_fn.extend([opera, opera_gx, safari])

for fn in browsers_fn:
    cookies = fn()
    print(f"{fn.__name__}: {len(cookies)} cookies")
