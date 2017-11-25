import functools

from aiohttp import web

from aiohttp_security import remember, forget, authorized_userid, permits

from .db_auth import check_credentials

from aiohttp_jinja2 import template, render_string

from base64 import b64decode

import logging
logger = logging.getLogger(__name__)


def require(permission):
    def wrapper(f):
        @functools.wraps(f)
        async def wrapped(self, request):
            has_perm = await permits(request, permission)
            if not has_perm:
                message = render_string('no_permission.jinja2',
                                        request,
                                        {'permission': permission})
                raise web.HTTPForbidden(body=message, content_type='text/html')
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
        auth_headers = request.headers.getall('Authorization', [])
        if auth_headers == []:
            return web.HTTPUnauthorized(
                body='No username/password specified')

        auth_header = auth_headers[0]
        if not auth_header.startswith('Basic '):
            return web.HTTPUnauthorized(
                body=f'Corrupted Authorization header: "{auth_header}"')

        base64_string = auth_header.split(' ')[-1]
        decoded_header = b64decode(base64_string).decode('utf-8')

        if not ':' in decoded_header:
            return web.HTTPUnauthorized(
                body=f'Corrupted base64 string: "{decoded_header}"')

        login, password = decoded_header.split(':')
        logger.info(f"Using '{login}' and '{password}'")

        db_engine = request.app.db_engine
        if not await check_credentials(db_engine, login, password):
            return web.HTTPUnauthorized(
                body=f'Incorrect username/password combination')

        res = {'sub': login}
        response = web.json_response(res)
        await remember(request, response, login)
        return response

    @require('public')
    @template('logout.jinja2')
    async def logout(self, request):
        message = b'You have been logged out'
        response = web.Response(body=message)
        await forget(request, response)
        return {'message': message.decode('utf-8')}

    def configure(self, app):
        router = app.router
        router.add_route('GET', '/', self.index, name='index')
        router.add_route('GET', '/login', self.login_openshift, name='login_openshift')
        router.add_route('POST', '/login', self.login, name='login')
        router.add_route('GET', '/logout', self.logout, name='logout')
