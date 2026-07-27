import hashlib


def hashes(text):
    raw = text.encode('utf-8')
    return {name: getattr(hashlib, name)(raw).hexdigest() for name in ('md5', 'sha1', 'sha256', 'sha512')}
