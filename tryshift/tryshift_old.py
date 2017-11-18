from aiohttp import web
import time
import base64
from cryptography import fernet
from aiohttp import web
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage

import json
import patreon
from urllib.parse import urljoin

import asyncio
import aiohttp

client_id = '234f74b9a60a20d6c5c455982c108ea7d6c09c66885a2e083a7f1f5b96d908d4'
client_secret = '462e95f927221933d905f407d3b637f68c18fdecb654d94002a2629caef1fe6e'
cluster_url = "https://127.0.0.1:8443/oauth/authorize"
redirect_url = "https://tryshift.aracan.ga/redirect"

#creator_token = 'kUhr8dx9peUdtmBeLVVTGD1Hsme4cf_D26SNkZP__1g'

async def oauth_login(request):
    print("new login:", request.query,request.headers)

    # Save state and redirect_url for this session
    session = await get_session(request)
    session['client_id'] = request.query['client_id']
    session['redirect_uri'] = request.query['redirect_uri']

    url = "https://www.patreon.com/oauth2/authorize" + \
          "?response_type=code" + \
          "&client_id={}".format(client_id) + \
          "&redirect_uri={}".format(redirect_url) + \
          "&state={}".format(request.query['state'])
    print(url)
    request.headers['X-Csrf-Token'] = '1'
    if 'X-Remote-User' in request.headers:
        import pdb; pdb.set_trace()
        del request.headers['X-Remote-User']
    return web.HTTPMovedPermanently(url, headers=request.headers)

async def redirect(request):
    print("redirected:", request.query)
    if 'X-Remote-User' in request.headers:
        import pdb; pdb.set_trace()

    oauth_client = patreon.OAuth(client_id, client_secret)
    tokens = oauth_client.get_tokens(request.query.get('code'), redirect_url)
    if 'access_token' not in tokens:
        return web.json_response(tokens)

    print("access token fetched")
    #Fetch user info
    user_status = None
    api_client = patreon.API(tokens['access_token'])
    user_response = api_client.fetch_user()
    user = user_response.data()
    user_id = user.id()
    user_full_name = user.attribute('full_name')
    user_email = user.attribute('email')
    user_login = user.attribute('vanity')
    print("user info fetched")

    # Check if user is a campaign admin
    # campaign_client = patreon.API(creator_token)
    # campaign_response = campaign_client.fetch_campaign_and_patrons()
    # if isinstance(campaign_response, dict):
    #     return web.json_response(campaign_response)
    # print("campaign_response:", campaign_response)
    # campaign_id = campaign_response.data()[0].id()
    #
    # users_pleges = {}
    # pledges = []
    # cursor = None
    # while True:
    #     pledges_response = campaign_client.fetch_page_of_pledges(campaign_id, 10, cursor=cursor)
    #     pledges += pledges_response.data()
    #     cursor = campaign_client.extract_cursor(pledges_response)
    #     if not cursor:
    #         break
    # for pledge in pledges:
    #     users_pleges[pledge.relationship('patron').id()] = pledge.attribute('amount_cents')
    # print("users_pleged:", users_pleges.keys())
    #
    # if user_id == campaign.relationship("creator").id():
    #     status = "creator"
    # if user_id in users_pleges:
    #     status = "pleged"
    # print("User status:", pledged)

    # Set user header
    headers = {}
    headers = request.headers.copy()
    if user_full_name:
        headers['X-Remote-User-Display-Name'] = user_full_name
    if user_email:
        headers['X-Remote-User-Email'] = user_email
    if user_login:
        headers['X-Remote-User-Login'] = user_login

    headers['X-Remote-User'] = user_id
    print("Headers ", headers)

    # TODO: set state here and get cluster_url from redirect
    session = await get_session(request)
    #result_url = "{cluster_url}?code={code}&state={state}&client_id={client_id}".format(
    #   cluster_url=session['redirect_uri'],
    #   state=request.query["state"],
    #   code=request.query["code"],
    #   client_id=session['client_id'])
    result_url = "https://127.0.0.1:8443/console"
    print(result_url)
    headers['location'] = result_url
    return web.Response(
        status=302,
        headers=headers
    )

async def proxy(request):
    print("proxy+")
    target_url = urljoin("https://127.0.0.1:8443", request.match_info['path'])

    request.headers['X-Remote-User'] = 'joe'

    data = await request.read()
    get_data = request.rel_url.query
    async with aiohttp.ClientSession() as session:
        async with session.request(request.method, target_url, headers=request.headers, params=get_data, data=data, verify_ssl=False) as resp:
            res = resp
            raw = await res.read()

    return web.Response(body=raw, status=res.status, headers=res.headers)

app = web.Application(debug=True)

# secret_key must be 32 url-safe base64-encoded bytes
fernet_key = fernet.Fernet.generate_key()
secret_key = base64.urlsafe_b64decode(fernet_key)
setup(app, EncryptedCookieStorage(secret_key))

app.router.add_route('*', '/login/authorize', oauth_login)
app.router.add_route('*', '/redirect', redirect)
app.router.add_route('*', '/{path:.*?}', proxy)

web.run_app(app)
