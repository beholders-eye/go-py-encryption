from base64 import b64encode
import binascii
import subprocess

from Crypto import Cipher
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto import Random
from Crypto.Hash import HMAC, SHA256

key = b'shameful scene, the one that doe'
data = b"Helvetios cause we're wrong, and we are actually very damn wrong"
header = b'Amanda'

def seal_patch_chacha_poly(raw_data):

    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(raw_data)

    return ciphertext, tag, cipher.nonce

enc, tag, nonce = seal_patch_chacha_poly(data)

enc = b64encode(enc).decode('utf-8')
nonce = b64encode(nonce).decode('utf-8')
tag = b64encode(tag).decode('utf-8')

print('Encrypted: "%s"' % enc)
print('Nonce: "%s"' % nonce)
print('Tag: "%s"' % tag)

print('\nCalling ./godec -data %s -nonce %s' % (enc, nonce))

subprocess.run(['./godec', '-data', enc, '-nonce', nonce, '-tag', tag])
