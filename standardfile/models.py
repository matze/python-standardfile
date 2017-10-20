import os
import base64
import hmac
import hashlib
import json
import datetime
import uuid as uuid_module
from binascii import unhexlify, hexlify
from client import AuthenticationError
from Crypto.Cipher import AES


class Item(object):
    def __init__(self, uuid, content_type, created_at, updated_at, content, deleted=False):
        self.uuid = uuid or str(uuid_module.uuid4())
        self.content_type = content_type
        self.created_at = created_at or datetime.datetime.now()
        self.updated_at = updated_at or datetime.datetime.now()
        self.content = content
        self.deleted = deleted

    def __repr__(self):
        return "<Item:type={}>".format(self.content_type)

    @property
    def references(self):
        return self.content['references']


class Note(Item):
    def __init__(self, uuid=None, created_at=None, updated_at=None,
                 content=dict(references=[]), title=None, text=None):
        super(Note, self).__init__(uuid, 'Note', created_at, updated_at, content)

        if title:
            self.title = title

        if text:
            self.text = text

    @property
    def title(self):
        return self.content['title'].encode('utf-8')

    @title.setter
    def title(self, t):
        self.content['title'] = t

    @property
    def text(self):
        return self.content.get('text', '')

    @text.setter
    def text(self, t):
        self.content['text'] = t

    def __repr__(self):
        return "<Note:title={}>".format(self.title)


class Tag(Item):
    def __init__(self, uuid=None, created_at=None, updated_at=None,
                 content=dict(references=[]), title=None):
        super(Tag, self).__init__(uuid, 'Tag', created_at, updated_at, content)

        if title:
            self.title = title

    @property
    def title(self):
        return self.content['title'].encode('utf-8')

    @title.setter
    def title(self, t):
        self.content['title'] = t


class Collection(object):
    def __init__(self, items):
        self.items = {x.uuid: x for x in items}
        self.notes = [x for x in items if isinstance(x, Note)]
        self.tags = [x for x in items if isinstance(x, Tag)]

    def refs_for(self, item):
        return [self.items[ref['uuid']] for ref in item.references]

    def tag_matching(self, name):
        matches = [x for x in self.tags if x.title == name]
        return matches[0] if matches else None


def decrypt_001(data, master_key, auth_key):
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


def decrypt_002(data, master_key, auth_key):
    def decrypt_string(s, enc_key, auth_key, check_uuid):
        version, auth_hash, uuid, iv, cipher_text = s.split(':')

        if uuid != check_uuid:
            raise AuthenticationError("uuid is wrong")

        string_to_auth = ':'.join((version, uuid, iv, cipher_text))
        hmac_sha256 = hmac.new(auth_key, string_to_auth, hashlib.sha256)

        if hmac_sha256.hexdigest() != auth_hash:
            raise AuthenticationError("Could not verify authentication hash")

        aes = AES.new(enc_key, AES.MODE_CBC, unhexlify(iv))
        result = aes.decrypt(base64.b64decode(cipher_text))
        return result[:-ord(result[-1])]

    uuid = data['uuid']
    item_key = decrypt_string(data['enc_item_key'], unhexlify(master_key), unhexlify(auth_key), uuid)
    item_enc_key = item_key[:len(item_key) / 2]
    item_auth_key = item_key[len(item_key) / 2:]
    content = decrypt_string(data['content'], unhexlify(item_enc_key), unhexlify(item_auth_key), uuid)
    return json.loads(content)


def decrypt(data, master_key, auth_key):
    prefix = data['content'][:3]

    if prefix == '001':
        return decrypt_001(data, master_key, auth_key)

    if prefix == '002':
        return decrypt_002(data, master_key, auth_key)

    raise RuntimeError("Unknown encryption scheme")


def load(data, master_key, auth_key):
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    created_at = datetime.datetime.strptime(data['created_at'], fmt)
    updated_at = datetime.datetime.strptime(data['updated_at'], fmt)

    if 'deleted' in data and data['deleted']:
        return Item(data['uuid'], 'Note', created_at, updated_at, data['content'], True)

    if data['content_type'] == 'Note':
        content = decrypt(data, master_key, auth_key)
        return Note(data['uuid'], created_at, updated_at, content)

    if data['content_type'] == 'Tag':
        content = decrypt(data, master_key, auth_key)
        return Tag(data['uuid'], created_at, updated_at, content)

    return Item(data['uuid'], 'Note', created_at, updated_at, data['content'])


def encrypt_001(item, master_key):
    """Returns a tuple (enc_content, enc_item_key, auth_hash)"""
    content = json.dumps(item.content)
    length = 16 - (len(content) % 16)
    content += chr(length)*length

    item_key = os.urandom(64)
    enc_key = item_key[:32]
    auth_key = item_key[32:]
    iv = '\0'*16
    aes = AES.new(enc_key, AES.MODE_CBC, iv)
    enc_content = "001" + base64.b64encode(aes.encrypt(content))
    auth_hash = hmac.new(auth_key, enc_content, hashlib.sha256).hexdigest()

    aes = AES.new(unhexlify(master_key), AES.MODE_CBC, iv)

    # add unnecessary 16-byte padding because CryptoJS is an asshole
    enc_item_key = base64.b64encode(aes.encrypt(hexlify(item_key) + chr(16)*16))
    return enc_content, enc_item_key, auth_hash


def encrypt_002(item, master_key):
    """Returns a tuple (enc_content, enc_item_key)"""
    def encrypt(s, enc_key, auth_key):
        length = 16 - (len(s) % 16)
        s += chr(length)*length

        iv = os.urandom(16)
        aes = AES.new(enc_key, AES.MODE_CBC, iv)
        encrypted = base64.b64encode(aes.encrypt(s))

        iv = hexlify(iv)
        auth_hash = hmac.new(auth_key, ":".join(["002", iv, encrypted])).hexdigest()
        return ":".join(["002", auth_hash, iv, encrypted])

    item_key = os.urandom(64)
    enc_key = item_key[:32]
    auth_key = item_key[32:]

    enc_content = encrypt(json.dumps(item.content), enc_key, auth_key)

    global_enc_key = hmac.new(master_key, 'e', hashlib.sha256).digest()
    global_auth_key = hmac.new(master_key, 'a', hashlib.sha256).digest()
    enc_item_key = encrypt(hexlify(item_key), global_enc_key, global_auth_key)

    return enc_content, enc_item_key


def dump(item, master_key):
    def normalize(s):
        return s[:-3] + 'Z'

    fmt = "%Y-%m-%dT%H:%M:%S.%f"
    content, enc_item_key, auth_hash = encrypt_001(item, master_key)

    data = dict(
        uuid=item.uuid,
        created_at=normalize(datetime.datetime.strftime(item.created_at, fmt)),
        updated_at=normalize(datetime.datetime.strftime(item.updated_at, fmt)),
        content_type=item.content_type,
        deleted=item.deleted,
        content=content,
        enc_item_key=enc_item_key,
        auth_hash=auth_hash,
    )

    return data
