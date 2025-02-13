import sys
import urllib.parse
from auth_util import generate_jwt, load_private_key


def urlencode(text):
	return urllib.parse.quote(text)


def generate_url(url, asset, user, **kwargs):

    private_key_path = f'credentials/{user}'
    private_key = load_private_key(private_key_path)

    signature = generate_jwt(user, private_key)

    if not url.endswith('asset='):
        if not url.endswith('?'):
            url += '?'
        url += 'asset='
    url += asset
    url += '&html=1'
    url += f'&user={user}'
    for key, value in kwargs.items():
        url += f'&{key}={urlencode(value)}'
    url += '&auth='
    url += urlencode(signature)

    return url


