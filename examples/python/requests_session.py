"""Attach a Chrome profile to a requests.Session."""

import requests
from rookie_cookies import jar


def create_session() -> requests.Session:
    session = requests.Session()
    session.cookies = jar(browser="chrome", profile="Default")
    return session


session = create_session()
session.get("https://example.com/", timeout=10)
