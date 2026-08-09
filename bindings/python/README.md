# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie)

## Usage

```python
from rookie_cookies import chrome
cookies = chrome()
for cookie in cookies:
    print(cookie['domain'], cookie['name'])
```
