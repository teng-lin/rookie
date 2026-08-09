import rookie_cookies
import requests

def create_session() -> requests.Session:
    """
    Create requests session with cookiejar that contains web browsers cookies
    """
    # Load cookies from browser
    cookies = rookie_cookies.load()
    # Create Cookiejar from cookies
    cj = rookie_cookies.to_cookiejar(cookies)
    # Create session
    session = requests.session()
    # Set session cookiejar
    session.cookies = cj
    return session

session = create_session()
session.get('https://google.com/')