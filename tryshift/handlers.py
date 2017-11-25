import functools

from aiohttp import web

from aiohttp_security import remember, forget, authorized_userid, permits

from .db_auth import check_credentials

from aiohttp_jinja2 import template

import logging
logger = logging.getLogger(__name__)


def require(permission):
    def wrapper(f):
        @functools.wraps(f)
        async def wrapped(self, request):
            has_perm = await permits(request, permission)
            if not has_perm:
                message = f'User has no "{permission}" permission'
                raise web.HTTPForbidden(body=message)
            return (await f(self, request))
        return wrapped
    return wrapper


class Web(object):
    @template('home.jinja2')
    async def index(self, request):
        username = await authorized_userid(request)
        message = f'Hello, {username}!' if username else 'You need to login'
        return {'message': message}

    @template('login.jinja2')
    async def login(self, request):
        response = web.HTTPFound('/')
        form = await request.post()
        login = form.get('login')
        password = form.get('password')
        db_engine = request.app.db_engine
        if (await check_credentials(db_engine, login, password)):
            await remember(request, response, login)
            return response

        return web.HTTPUnauthorized(
            body='Invalid username/password combination')

    async def login_openshift(self, request):
        response = web.HTTPFound('/')
        form = await request.post()
        logger.info(form)
        login = form.get('login')
        password = form.get('password')
        db_engine = request.app.db_engine
        if (await check_credentials(db_engine, login, password)):
            await remember(request, response, login)
            return response

    @require('public')
    @template('logout.jinja2')
    async def logout(self, request):
        await forget(request, response)
        return {'message': 'You have been logged out'}

    def configure(self, app):
        router = app.router
        router.add_route('GET', '/', self.index, name='index')
        router.add_route('GET', '/login', self.login_openshift, name='login_openshift')
        router.add_route('POST', '/login', self.login, name='login')
        router.add_route('GET', '/logout', self.logout, name='logout')
