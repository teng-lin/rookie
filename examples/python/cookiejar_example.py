from rookie_cookies import brave, to_cookiejar

cookies = brave()
cj = to_cookiejar(cookies)
print(cj)