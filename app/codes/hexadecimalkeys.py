"""Wallet manager"""
from unittest import skip
import ecdsa
from Crypto.Hash import keccak
import os
import json

def get_address_from_public_key(public_key):
    public_key_bytes = bytes.fromhex(public_key)

    wallet_hash = keccak.new(digest_bits=256)
    wallet_hash.update(public_key_bytes)
    keccak_digest = wallet_hash.hexdigest()

    address = '0x' + keccak_digest[-40:]
    return address

def generate_wallet_address():
    private_key_bytes = os.urandom(32)
    key_data = {'public': None, 'private': None, 'address': None}
    skey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) 
    vkey = skey.get_verifying_key()
    key = ecdsa.SigningKey.from_string(
        private_key_bytes, curve=ecdsa.SECP256k1).verifying_key

    key_bytes = key.to_string()

    private_key_hex = private_key_bytes.hex()
    public_key_hex = key_bytes.hex()
    key_data['address'] = get_address_from_public_key(public_key_hex)
    key_data['private'] = private_key_hex
    key_data['public'] = public_key_hex
    return key_data

def sign_object(private_key, data):
    pvtkeybytes = bytes.fromhex(private_key)
    msg = json.dumps(data).encode()
    sk = ecdsa.SigningKey.from_string(pvtkeybytes, curve=ecdsa.SECP256k1)
    msgsignbytes = sk.sign(msg)
    msgsign = msgsignbytes.hex()
    return msgsign

def validate_signature(data, public_key, signature):
    public_key_bytes = bytes.fromhex(public_key)
    sign_trans_bytes = bytes.fromhex(signature)
    vk = ecdsa.VerifyingKey.from_string(
        public_key_bytes, curve=ecdsa.SECP256k1)
    message = json.dumps(data).encode()
    try:
        return vk.verify(sign_trans_bytes, message)
    except:
        return False

keydata = generate_wallet_address()
msg="Hello World"
msgsign = sign_object(keydata['private'], msg)
print("msgsign is :", msgsign)
print(validate_signature(msg, keydata['public'],msgsign))
