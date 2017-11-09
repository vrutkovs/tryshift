import functools

from aiohttp import web

from aiohttp_security import remember, forget, authorized_userid, permits

from .db_auth import check_credentials

from aiohttp_jinja2 import template


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

    @require('public')
    @template('logout.jinja2')
    async def logout(self, request):
        await forget(request, response)
        return {'message': 'You have been logged out'}

    @require('public')
    @template('internal_page.jinja2')
    async def internal_page(self, request):
        return {'message': 'This page is visible for all registered users'}

    @require('protected')
    @template('protected.jinja2')
    async def protected_page(self, request):
        return {'message': 'You are on protected page'}

    def configure(self, app):
        router = app.router
        router.add_route('GET', '/', self.index, name='index')
        router.add_route('POST', '/login', self.login, name='login')
        router.add_route('GET', '/logout', self.logout, name='logout')
        router.add_route('GET', '/public', self.internal_page, name='public')
        router.add_route('GET', '/protected', self.protected_page, name='protected')
