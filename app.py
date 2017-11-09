import asyncio

from aiohttp import web
from aiohttp_session import setup as setup_session
from aiohttp_session.redis_storage import RedisStorage
from aiohttp_security import setup as setup_security
from aiohttp_security import SessionIdentityPolicy
from aiohttp_jinja2 import setup as setup_jinja
from jinja2 import FileSystemLoader
from aiopg.sa import create_engine
from aioredis import create_pool


from tryshift.db_auth import DBAuthorizationPolicy
from tryshift.handlers import Web

import logging
import logging.config

import sys

DEFAULT_LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'loggers': {
        'tryshift': {
            'level': 'INFO',
        },
        'aiohttp.access': {
            'level': 'DEBUG',
        },
        'aiohttp.web': {
            'level': 'DEBUG',
        }
    }
}


async def init(loop):
    redis_pool = await create_pool(('redis', 6379))
    db_engine = await create_engine(user='aiohttp_security',
                                    password='aiohttp_security',
                                    database='aiohttp_security',
                                    host='postgresql')
    app = web.Application(loop=loop, debug=True)
    app.db_engine = db_engine
    app.redis_pool = redis_pool
    setup_session(app, RedisStorage(redis_pool))
    setup_security(app,
                   SessionIdentityPolicy(),
                   DBAuthorizationPolicy(db_engine))
    setup_jinja(app, loader=FileSystemLoader('templates'))
    app.on_cleanup.append(dispose_redis_pool)

    web_handlers = Web()
    web_handlers.configure(app)

    handler = app.make_handler()
    srv = await loop.create_server(handler, '0.0.0.0', 8080)
    print('Server started at http://0.0.0.0:8080')
    return srv, app, handler


async def dispose_redis_pool(app):
    app.redis_pool.close()
    await app.redis_pool.wait_closed()


async def finalize(srv, app, handler):
    sock = srv.sockets[0]
    app.loop.remove_reader(sock.fileno())
    sock.close()

    await handler.finish_connections(1.0)
    srv.close()
    await srv.wait_closed()
    await app.finish()


def setup_logging():
    logging.config.dictConfig(DEFAULT_LOGGING)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)


def main():
    setup_logging()

    loop = asyncio.get_event_loop()
    srv, app, handler = loop.run_until_complete(init(loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete((finalize(srv, app, handler)))


if __name__ == '__main__':
    main()
