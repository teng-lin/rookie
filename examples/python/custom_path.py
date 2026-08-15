from os import getenv
from pathlib import Path

import rookie_cookies

# Using pathlib and cross platform paths is always recommended!
localappdata = getenv('LOCALAPPDATA')
db_path = Path(localappdata) / 'BraveSoftware/Brave-Browser/User Data/default/network/Cookies'
key_path = Path(localappdata) / 'BraveSoftware/Brave-Browser/User Data/Local State'
cookies = rookie_cookies.chromium_cookies_from_path(
    str(db_path), {"local_state_path": str(key_path)}
)
print(cookies)
