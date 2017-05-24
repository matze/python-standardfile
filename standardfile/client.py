import requests
import base64
import standardfile.models
from passlib.hash import pbkdf2_sha512
from requests.compat import urljoin
from binascii import hexlify, unhexlify


class AuthenticationError(Exception):
    pass


class Client(object):
    def __init__(self, email, password, host='https://sync.standardnotes.org'):
        self.host = host
        self.token = self.sign_in(email, password)
        self.sync_token = None

    def url(self, relative):
        return urljoin(self.host, relative)

    def sign_in(self, email, password):
        params = requests.get(self.url('auth/params'), params=dict(email=email)).json()

        hash_params = dict(salt=bytes(params['pw_salt']), rounds=params['pw_cost'])
        hashed = pbkdf2_sha512.hash(password, **hash_params)
        hashed = hashed[hashed.rfind('$') + 1:].replace('.', '+') + '=='
        decoded = hexlify(base64.b64decode(hashed))

        password = decoded[:len(decoded) / 2]
        self.master = decoded[len(decoded) / 2:]
        resp = requests.post(self.url('auth/sign_in'), data=dict(email=email, password=password))

        if resp.status_code >= 400:
            raise AuthenticationError("E-mail or password wrong")

        return resp.json()

    def get(self):
        params = {'items': [], 'limit': 50}
        headers = {'Authorization': 'Bearer {}'.format(self.token['token'])}
        response = requests.post(self.url('items/sync'), headers=headers, json=params)
        data = response.json()
        return [standardfile.models.make(d, self.master) for d in data['retrieved_items']]
