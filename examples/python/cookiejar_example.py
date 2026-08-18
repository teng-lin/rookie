"""Load a browser profile into http.cookiejar (stdlib owns send-match)."""

from rookie_cookies import jar

cj = jar(browser="brave", profile="Default")
print(cj)
