import base64
import hmac
import hashlib
from client import AuthenticationError
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify


class Item(object):
    def __init__(self, data):
        self.uuid = data['uuid']
        self.created = data['created_at']
        self.updated = data['updated_at']
        self.content_type = data['content_type']

    def __repr__(self):
        return "<Item:created={}, type={}>".format(self.created, self.content_type)


class Note(Item):
    def __init__(self, data, master_key):
        super(Note, self).__init__(data)

        if not 'content' in data:
            raise ValueError("Note must contain `content' key")

        if data['content'][:3] == '001':
            enc_item_key = base64.b64decode(data['enc_item_key'])
            iv = enc_item_key[:16]
            aes = AES.new(unhexlify(master_key), AES.MODE_CBC, iv)
            item_key = aes.decrypt(enc_item_key)        # 144 bytes hex encoded data result
            item_key = item_key[16:-ord(item_key[-1])]  # 112 bytes hex encoded data remain (without IV and padding)

            item_key = '\0'*8 + unhexlify(item_key)
            enc_key = item_key[8:len(item_key) / 2 + 8]
            auth_key = item_key[len(item_key) / 2:]

            hmac_sha256 = hmac.new(auth_key, data['content'], hashlib.sha256)
        
            if hmac_sha256.hexdigest() != data['auth_hash']:
                raise AuthenticationError("Could not verify authentication hash")

            content = base64.b64decode(data['content'][3:])
            iv = content[:16]
            aes = AES.new(enc_key, AES.MODE_CBC, iv)
            d = aes.decrypt(content)

    def __repr__(self):
        return "<Note:created={}, updated={}>".format(self.created, self.updated)


def make(data, master_key):
    if 'deleted' in data and data['deleted']:
        return Item(data)

    if data['content_type'] == 'Note':
        return Note(data, master_key)

    return Item(data)
