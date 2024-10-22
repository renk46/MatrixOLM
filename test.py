import os
import based58
import base64
import hmac
import hashlib
import json

import binascii

from Crypto.Cipher import AES
from Crypto.Util import Counter

from olm import PkDecryption, PkMessage, InboundGroupSession, OutboundGroupSession

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from utils import print_bytes



input_key = ""
content = {
    "ciphertext": "",
    "iv": "",
    "mac": ""
}
message = PkMessage(
    "",
    "",
    ""
)



input_key = input_key.replace(' ', '')
input_key = based58.b58decode(bytes(input_key, "utf8"), alphabet=based58.Alphabet.BITCOIN)

input_key = input_key[2:-1]

salt = bytes([])
info = "m.megolm_backup.v1".encode()

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=64,
    salt=salt,
    info=info,
)
key = hkdf.derive(input_key)

aesKey = key[0:32]
hmacKey = key[32:]

ciphertextBytes = base64.b64decode(content["ciphertext"])
expected_signature = base64.b64decode(content["mac"])

signature = hmac.new(hmacKey, ciphertextBytes, hashlib.sha256).digest()

iv = base64.b64decode(content["iv"])

ctr = Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))
cipher = AES.new(aesKey, AES.MODE_CTR, counter=ctr)

privateKey = cipher.decrypt(ciphertextBytes)
privateKey = privateKey + b'===='

privateKey = base64.b64decode(privateKey)

decryption = PkDecryption()

from _libolm import ffi, lib

decryption._buf = ffi.new("char[]", lib.olm_pk_decryption_size())
decryption._pk_decryption = lib.olm_pk_decryption(decryption._buf)

key_length = lib.olm_pk_key_length()
key_buffer = ffi.new("char[]", key_length)

ret = lib.olm_pk_key_from_private(
    decryption._pk_decryption,
    key_buffer, key_length,
    privateKey, len(privateKey)
)

t = decryption.decrypt(message)
data = json.loads(t)

session_key = data['session_key']

session = InboundGroupSession.import_session(session_key)
pickle = session.pickle("DEFAULT_KEY")

print(pickle)

