import os, json
from base64 import b64decode
from io import BytesIO
from axolotl.kdf.hkdfv3 import HKDFv3
import hmac
import hashlib
from axolotl.util.byteutil import ByteUtil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import mimetypes
import uuid

import requests

def mediaTypes(type):
    return {
            'IMAGE': 'Image',
            'VIDEO': 'Video',
            'AUDIO': 'Audio',
            'PTT': 'Audio',
            'DOCUMENT': 'Document',
            'STICKER': 'Image'
        }.get(type.upper())

def download_file(url):
    return requests.get(url).content

def download_media(media_msg, force_download=False):
    if not force_download:
        try:
            if media_msg['content']:
                return BytesIO(b64decode(media_msg['content']))
        except AttributeError:
            pass

    ciphertext = download_file(media_msg['deprecatedMms3Url'])

    if not ciphertext:
        raise Exception('Impossible to download file')

    media_key = b64decode(media_msg['mediaKey'])
    derivative = HKDFv3().deriveSecrets(media_key,
                                        bytes(f'WhatsApp {mediaTypes(media_msg["type"])} Keys','utf-8'),
                                        112)

    parts = ByteUtil.split(derivative, 16, 32)
    iv = parts[0]
    key = parts[1]
    mac_key = derivative[48:80]
    media_ciphertext = ciphertext[:-10]
    mac_value = ciphertext[-10:]

    mac = hmac.new(mac_key, digestmod=hashlib.sha256)
    mac.update(iv)
    mac.update(media_ciphertext)

    if mac_value != mac.digest()[:10]:
        raise ValueError("Invalid MAC")

    cr_obj = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    cipher_decryptor = cr_obj.decryptor()

    decrypted = cipher_decryptor.update(media_ciphertext) + cipher_decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return BytesIO( unpadder.update(decrypted) + unpadder.finalize() )

def save_media(media_msg, path, force_download=False):
    if (media_msg['mimetype'].find(";")==-1):
        extension = mimetypes.guess_extension(media_msg['mimetype'])
    else:
        extension = mimetypes.guess_extension(media_msg['mimetype'][:media_msg['mimetype'].find(";")])

    filename = os.path.join(path, str(uuid.uuid4())+'.'+extension)
    ioobj = download_media(media_msg, force_download)
    with open(filename, "wb") as f:
        f.write(ioobj.getvalue())
    return filename

def json_reader(file):
    f = open(file, "r")
    c = f.read()
    f.close()
    return json.loads(c)

if (__name__=='__main__'):
    message = json_reader('arquivo.json')
    print(save_media(message,'.',force_download=True))
    print(save_media(message,'.',force_download=False))