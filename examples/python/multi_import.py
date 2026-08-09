import platform
from rookie_cookies import (
    arc,
    brave,
    chromium,
    chrome,
    edge,
    firefox,
    librewolf,
    vivaldi,
    zen,
)

# On all platforms
browsers_fn = [arc, brave, chromium, chrome, edge, firefox, librewolf, vivaldi]

# Linux
if platform.system() == "Linux":
    from rookie_cookies import cachy, opera

    browsers_fn.append(cachy)

# Windows
elif platform.system() == "Windows":
    from rookie_cookies import internet_explorer, opera, opera_gx

    browsers_fn.extend([internet_explorer, opera, opera_gx])

# macOS
elif platform.system() == "Darwin":
    from rookie_cookies import safari

    browsers_fn.extend([safari])

for fn in browsers_fn:
    cookies = fn()
    print(f"Found {len(cookies)} cookies!")
