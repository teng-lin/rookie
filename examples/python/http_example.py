"""Hit GitHub with cookies from a Brave profile.

Uses jar() so http.cookiejar does URL send-match. Never log cookie values.
"""

import re

import requests
from rookie_cookies import jar


def extract_username(html: str) -> str:
    match = re.search(r'<meta name="user-login" content="(.+)">', html)
    return match.group(1) if match else ""


def main() -> None:
    try:
        session = requests.Session()
        session.cookies = jar(browser="brave", profile="Default")
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/117.0.0.0 Safari/537.36"
        )
        response = session.get("https://github.com/", timeout=10)
        username = extract_username(response.text)
        if not username:
            print("Not logged in to GitHub")
        else:
            print(f"Logged in to GitHub as {username}")
    except requests.RequestException as error:
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    main()
