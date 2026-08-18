"""Turn on debug logging, then take a 0.6 snapshot."""

import logging

import rookie_cookies

FORMAT = (
    "%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s"
)
logging.basicConfig(format=FORMAT)
logging.getLogger().setLevel(logging.DEBUG)

rows = rookie_cookies.read(browser="chrome", profile="Default").as_list()
print(f"found {len(rows)} cookies")
