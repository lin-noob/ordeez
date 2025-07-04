import re
import uuid
import requests
from loguru import logger


def authorize_twitter(twitter_token, proxies=None, reauth_url: str = None):
    try:
        session = requests.session()
        session.proxies = proxies
        response = session.get(url='https://x.com/home', cookies={
            'auth_token': twitter_token,
            'ct0': '0c5e2198e01195f7d9d516b16f4460775334c0c93aa9f3af670349057dba92635a9bc6bb312925fd4098e68a7d5e30bbf418ec688a28c1301a3fb8c8d4ac9f1cb086fdcc42fd6ca064de93920bc6cf67'
        })
        ct0 = re.findall('ct0=(.*?);', dict(response.headers)['set-cookie'])[0]
        cookies = {'ct0': ct0, 'auth_token': twitter_token}
        params = {
            'response_type': 'code',
            'client_id': 'c1h0S1pfb010TEVBUnh2N3U3MU86MTpjaQ',
            'redirect_uri': 'https://pioneer.particle.network/signup',
            'scope': 'tweet.read users.read',
            'state': f'twitter-{uuid.uuid4()}',
            'code_challenge': 'challenge',
            'code_challenge_method': 'plain',
        }

        headers = {'authority': 'x.com', 'accept': '*/*', 'accept-language': 'en,zh-CN;q=0.9,zh;q=0.8',
                   'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                   'cache-control': 'no-cache', 'content-type': 'application/json', 'origin': 'https://x.com',
                   'pragma': 'no-cache', 'referer': reauth_url,
                   'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                   'x-csrf-token': ct0}

        # 'https://twitter.com/i/api/2/oauth2/authorize'

        response = session.get(reauth_url, params=None, cookies=cookies,
                               headers=headers).json()
        auth_code = response['auth_code']
        data = {'approval': True, 'code': auth_code}
        response = session.post('https://twitter.com/i/api/2/oauth2/authorize', json=data, cookies=cookies,
                                headers=headers).json()
        redirect_uri = response['redirect_uri']
        return redirect_uri
    except Exception as e:
        logger.error(e)
