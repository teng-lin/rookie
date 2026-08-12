# rookie-cookies Python Docs

## Install

```console
pip3 install -U rookie-cookies
```

## Basic Usage

```python
import rookie_cookies
cookies = rookie_cookies.chrome() # Load cookies from Chrome
```

## Reports

`chrome()` and its siblings return a flat cookie list and raise on failure.
The report API instead covers every installation and profile of a browser and
keeps failures visible:

```python
import rookie_cookies

report = rookie_cookies.browser_report("chrome")  # or load_report() for all browsers
print(report["status"], report["summary"]["cookies_emitted"])

for profile in report["profiles"]:
    for source in profile["sources"]:
        if source["selected"] and source["status"] == "succeeded":
            print(source["source"]["path"], len(source["cookies"]))
```

`supported_browsers()` lists what this build knows about (registration, not
detection) and `browser_profiles(browser_id)` lists what is actually installed,
including the `profile_id` that `browser_report(browser_id, profile_id)` takes.

Every DTO is a dictionary with snake_case keys, and every identifier or code is
an open snake_case string rather than a closed set, so keep a fallback when
matching one.

## Logging

Logging level can be controlled by using the `logging` module

```python
import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
```

To fully disable `rookie_cookies` logging you can set the level to `CRITICAL`

```python
import logging
logging.getLogger().setLevel(logging.CRITICAL)
```
