# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie-cookies)

## Usage

```python
from rookie_cookies import chrome
cookies = chrome()
for cookie in cookies:
    print(cookie['domain'], cookie['name'])
```

## Firefox profiles

```python
from rookie_cookies import firefox_profile, firefox_profiles

for profile in firefox_profiles():
    print(profile["name"], profile["path"], profile["is_default"])

cookies = firefox_profile("work", ["example.com"])
```

## Netscape export

```python
from rookie_cookies import chrome, to_netscape

output = to_netscape(chrome())
```

The serializer prevents extra columns or forged records by encoding tabs,
carriage returns, and line feeds in cookie-controlled fields as `%09`, `%0D`,
and `%0A`. Every other character is preserved. Its output is byte-identical to
the Rust, CLI, and Node serializers for the same cookies.
