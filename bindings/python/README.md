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
