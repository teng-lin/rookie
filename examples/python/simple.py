"""Recommended 0.6 entry: session import via jar / read.

Pass profile= to include session cookies. Named helpers such as chrome()
remain for compatibility — see multi_import.py.
"""

import rookie_cookies as cookies

session_jar = cookies.jar(browser="chrome", profile="Default")
print(f"jar size: {len(list(session_jar))}")

rows = cookies.read(browser="chrome", profile="Default").as_list()
for row in rows[:5]:
    print(row["domain"], row["name"])
