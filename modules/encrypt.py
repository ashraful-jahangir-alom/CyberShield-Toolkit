import base64
import binascii
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12


def generate_key():
    """Return a URL-safe base64 encoded 256-bit AES key."""
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256))


def _decode(key):
    raw = base64.urlsafe_b64decode(key)
    if len(raw) != 32:
        raise ValueError('Key must be a base64-encoded 256-bit AES key.')
    return raw


def encrypt(data, key):
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(_decode(key)).encrypt(nonce, data, None)


def decrypt(data, key):
    if len(data) <= NONCE_SIZE:
        raise ValueError('Encrypted data is incomplete.')
    return AESGCM(_decode(key)).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], None)


def valid_key(key):
    try:
        _decode(key)
        return True
    except (ValueError, TypeError, binascii.Error):
        return False
