import logging
import rookie_cookies

FORMAT = '%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s'
logging.basicConfig(format=FORMAT)
logging.getLogger().setLevel(logging.DEBUG)
cookies = rookie_cookies.load()
print(f'found {len(cookies)} cookies')