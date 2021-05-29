import os, json
from base64 import b64decode
from io import BytesIO
from aiofile import AIOFile
import aiohttp
from axolotl.kdf.hkdfv3 import HKDFv3
from axolotl.util.byteutil import ByteUtil
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import mimetypes
import asyncio
import uuid

def mediaTypes(type):
    return {
            'IMAGE': 'Image',
            'VIDEO': 'Video',
            'AUDIO': 'Audio',
            'PTT': 'Audio',
            'DOCUMENT': 'Document',
            'STICKER': 'Image'
        }.get(type.upper())

async def magix(fileData, mediaKeyBase64, mediaType: str, expectedSize: int=None):
    mediaKeyBytes = b64decode(mediaKeyBase64)
    info = bytes(f'WhatsApp {mediaTypes(mediaType)} Keys','utf-8')
    derivative = HKDFv3().deriveSecrets(mediaKeyBytes,info,112)    

    parts = ByteUtil.split(derivative, 16, 32)
    iv = parts[0]
    key = parts[1]
    mac_key = derivative[48:80]
    media_ciphertext = fileData[:-10]
    mac_value = fileData[-10:]

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

def processUA(userAgent: str=None):
    ua = userAgent if (userAgent is not None) else 'WhatsApp/2.16.352 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36'
    if 'WhatsApp' not in ua:
        ua = "WhatsApp/2.16.352 " + ua
    return ua

def makeOptions(useragentOverride):
    return {
            'headers': {
                'User-Agent': processUA(useragentOverride),
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1',
                'origin': 'https://web.whatsapp.com/',
                'referer': 'https://web.whatsapp.com/'
                }
    }

async def download_enc_file(url, useragentOverride):
    options = makeOptions(useragentOverride)
    async with aiohttp.ClientSession(headers=options['headers']) as session:
        async with session.get(url) as r:
            if (r.status != 200):
                raise Exception('This media does not exist, or is no longer available on the server. Please see: https://docs.openwa.dev/pages/How%20to/decrypt-media.html#40439d')
            return await r.read()

async def decryptMedia(message: json, useragentOverride: str=None):
    url = message.get('clientUrl',message.get('deprecatedMms3Url'))
    buff = await download_enc_file(url,useragentOverride)
    return await magix(buff, message['mediaKey'], message['type'], message['size'])

async def download_media(message, force_download=False):
    if force_download:
        return await decryptMedia(message)
    else:
        try:
            if message['content']:
                return BytesIO(b64decode(message['content']))
        except AttributeError:
            raise AttributeError

async def save_media(message, path, force_download=False):
    content = await download_media(message, force_download)

    if (message['mimetype'].find(";")==-1):
        extension = mimetypes.guess_extension(message['mimetype'])
    else:
        extension = mimetypes.guess_extension(message['mimetype'][:message['mimetype'].find(";")])

    filename = os.path.join(path, str(uuid.uuid4())+extension)

    async with AIOFile(filename, 'wb') as f:
        await f.write(content.read())
    return filename

async def json_reader(file):
        j = ""
        async with AIOFile(file, 'r') as f:
            data = await f.read()
            j += data
        return json.loads(j)

async def main():
    message = await json_reader("arquivo.json")
    filename = await save_media(message, '.', force_download=True)
    print(f'Arquivo salvo como {filename}')

    filename = await save_media(message, '.', force_download=False)
    print(f'Arquivo salvo como {filename}')

if __name__== "__main__":
    asyncio.run(main())
    
    from downloader import json_reader as sync_json_reader
    j = sync_json_reader('arquivo.json')
    from downloader import save_media as sync_save_media
    sync_save_media(j,'.',True)
    sync_save_media(j,'.',False)
    