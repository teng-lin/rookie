"""Compatibility flatten: every registered browser the loader knows.

New code that wants one browser should use read()/jar() with a profile.
load() stays the historical all-browser merge.
"""

from rookie_cookies import load

cookies = load()
for cookie in cookies:
    print(f'domain: {cookie["domain"]} name: {cookie["name"]}')
