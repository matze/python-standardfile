import os
import base64
import hmac
import hashlib
import json
import binascii
import datetime
from client import AuthenticationError
from Crypto.Cipher import AES


class Item(object):
    def __init__(self, uuid, content_type, created_at, updated_at, content, deleted=False):
        self.uuid = uuid
        self.content_type = content_type
        self.created_at = created_at
        self.updated_at = updated_at
        self.content = content
        self.deleted = deleted

    def __repr__(self):
        return "<Item:type={}>".format(self.content_type)


class Note(Item):
    def __init__(self, uuid, content_type, created_at, updated_at, content):
        super(Note, self).__init__(uuid, content_type, created_at, updated_at, content)

    @property
    def title(self):
        return self.content['title']

    @property
    def text(self):
        return self.content['text']


class Tag(Item):
    def __init__(self,  uuid, content_type, created_at, updated_at, content):
        super(Tag, self).__init__(uuid, content_type, created_at, updated_at, content)

    @property
    def title(self):
        return self.content['title']


def decrypt_001(data, master_key):
    enc_item_key = base64.b64decode(data['enc_item_key'])
    iv = '\0'*16
    aes = AES.new(binascii.unhexlify(master_key), AES.MODE_CBC, iv)
    item_key = aes.decrypt(enc_item_key)
    item_key = binascii.unhexlify(item_key[:-16])

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


def load(data, master_key):
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    created_at = datetime.datetime.strptime(data['created_at'], fmt)
    updated_at = datetime.datetime.strptime(data['updated_at'], fmt)

    if 'deleted' in data and data['deleted']:
        return Item(data['uuid'], 'Note', created_at, updated_at, data['content'], True)

    if data['content_type'] == 'Note':
        content = decrypt(data, master_key)
        return Note(data['uuid'], 'Note', created_at, updated_at, content)

    if data['content_type'] == 'Tag':
        content = decrypt(data, master_key)
        return Note(data['uuid'], 'Tag', created_at, updated_at, content)

    return Item(data['uuid'], 'Note', created_at, updated_at, data['content'])


def encrypt_002(item, master_key):
    """Returns a tuple (enc_content, enc_item_key)"""
    def encrypt(s, enc_key, auth_key):
        length = 16 - (len(s) % 16)
        s += chr(length)*length

        iv = os.urandom(16)
        aes = AES.new(enc_key, AES.MODE_CBC, iv)
        encrypted = base64.b64encode(aes.encrypt(s))

        iv = binascii.hexlify(iv)
        auth_hash = hmac.new(auth_key, ":".join(["002", iv, encrypted])).hexdigest()
        return ":".join(["002", auth_hash, iv, encrypted])

    item_key = os.urandom(64)
    enc_key = item_key[:32]
    auth_key = item_key[32:]

    enc_content = encrypt(json.dumps(item.content), enc_key, auth_key)

    global_enc_key = hmac.new(master_key, 'e', hashlib.sha256).digest()
    global_auth_key = hmac.new(master_key, 'a', hashlib.sha256).digest()
    enc_item_key = encrypt(binascii.hexlify(item_key), global_enc_key, global_auth_key)

    return enc_content, enc_item_key


def dump(item, master_key):
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    content, enc_item_key = encrypt_002(item, master_key)

    data = dict(
        uuid=item.uuid,
        created_at=datetime.datetime.strftime(item.created_at, fmt),
        updated_at=datetime.datetime.strftime(item.updated_at, fmt),
        content_type=item.content_type,
        deleted=item.deleted,
        content=content,
        enc_item_key=enc_item_key,
    )

    return data
