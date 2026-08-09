import re

import requests
from rookie_cookies import brave, to_cookiejar


def extract_username(html):
    re_pattern = r'<meta name="user-login" content="(.+)">'
    match = re.search(re_pattern, html)
    if match:
        return match.group(1)
    return ""


def main():
    try:
        # Create a custom cookie store
        cookies = brave(["github.com"])
        cj = to_cookiejar(cookies)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        }
        response = requests.get(
            "https://github.com/", cookies=cj, headers=headers, timeout=10
        )
        content = response.text
        username = extract_username(content)
        if not username:
            print("Not logged in to GitHub")
        else:
            print(f"Logged in to GitHub as {username}")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")


main()
