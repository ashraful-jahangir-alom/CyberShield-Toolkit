import ipaddress
from urllib.parse import urlparse


def normalize_target(value):
    value = value.strip()
    if not value:
        raise ValueError('A target is required.')
    parsed = urlparse(value if '://' in value else f'https://{value}')
    host = parsed.hostname
    if not host or len(host) > 253:
        raise ValueError('Enter a valid domain, URL, or IP address.')
    return host


def is_private_target(host):
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def authorization_notice():
    return 'Run scans only against systems you own or are explicitly authorized to assess.'
