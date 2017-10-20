import requests
import base64
import binascii
import standardfile.models
import hashlib
from requests.compat import urljoin


class AuthenticationError(Exception):
    pass


class Client(object):
    def __init__(self, email, password, host='https://sync.standardnotes.org'):
        self.host = host
        self.token = self.sign_in(email, password)['token']
        self.headers = {'Authorization': 'Bearer {}'.format(self.token)}
        self.sync_token = None

    def url(self, relative):
        return urljoin(self.host, relative)

    def sign_in(self, email, password):
        params = requests.get(self.url('auth/params'), params=dict(email=email)).json()
        hashed = hashlib.pbkdf2_hmac('sha512', password, params['pw_salt'], params['pw_cost'], dklen=768/8)
        decoded = binascii.hexlify(hashed)

        length = len(decoded) / 3
        password = decoded[:length]
        self.master_key = decoded[length:2*length]
        self.auth_key = decoded[2*length:]
        resp = requests.post(self.url('auth/sign_in'), data=dict(email=email, password=password))

        if resp.status_code >= 400:
            raise AuthenticationError("E-mail or password wrong")

        return resp.json()

    def get(self):
        params = {'items': []}
        response = requests.post(self.url('items/sync'), headers=self.headers, json=params)
        data = response.json()
        return [standardfile.models.load(d, self.master_key) for d in data['retrieved_items']]

    def post(self, items):
        params = {'items': [standardfile.models.dump(x, self.master_key) for x in items], 'sync_token': ''}
        response = requests.post(self.url('items/sync'), headers=self.headers, json=params)
        data = response.json()
