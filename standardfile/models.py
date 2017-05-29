import base64
import hmac
import hashlib
from client import AuthenticationError
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify


def decrypt_001(data, master_key):
    enc_item_key = base64.b64decode(data['enc_item_key'])
    iv = '\0'*16
    aes = AES.new(unhexlify(master_key), AES.MODE_CBC, iv)
    item_key = aes.decrypt(enc_item_key)
    item_key = unhexlify(item_key[:-16])

    enc_key = item_key[:len(item_key) / 2]
    auth_key = item_key[len(item_key) / 2:]

    hmac_sha256 = hmac.new(auth_key, data['content'], hashlib.sha256)

    if hmac_sha256.hexdigest() != data['auth_hash']:
        raise AuthenticationError("Could not verify authentication hash")

    content = base64.b64decode(data['content'][3:])
    aes = AES.new(enc_key, AES.MODE_CBC, iv)
    content = aes.decrypt(content)
    return json.loads(content[:-ord(content[-1])])


def decrypt(data, master_key):
    if data['content'][:3] == '001':
        return decrypt_001(data, master_key)

    raise RuntimeError("002 not supported yet")


class Item(object):
    def __init__(self, data):
        self.uuid = data['uuid']
        self.created = data['created_at']
        self.updated = data['updated_at']
        self.content_type = data['content_type']

    def __repr__(self):
        return "<Item:type={}, created={}, updated={}>".format(self.content_type, self.created, self.updated)


class EncryptedItem(Item):
    def __init__(self, data, master_key):
        super(EncryptedItem, self).__init__(data)
        self.content = decrypt(data, master_key)


class Note(EncryptedItem):
    def __init__(self, data, master_key):
        super(Note, self).__init__(data, master_key)


class Tag(EncryptedItem):
    def __init__(self, data, master_key):
        super(Tag, self).__init__(data, master_key)


def make(data, master_key):
    if 'deleted' in data and data['deleted']:
        return Item(data)

    if data['content_type'] == 'Note':
        return Note(data, master_key)

    if data['content_type'] == 'Tag':
        return Tag(data, master_key)

    return Item(data)
