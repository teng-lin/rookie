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
