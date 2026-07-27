import socket
try:
    import whois
except ImportError:
    whois = None


def lookup(domain):
    result = {'ip_address': socket.gethostbyname(domain), 'reverse_dns': socket.gethostbyaddr(socket.gethostbyname(domain))[0] if domain else ''}
    if whois:
        try:
            record = whois.whois(domain)
            result.update({'registrar': str(record.registrar or ''), 'creation_date': str(record.creation_date or ''), 'expiration_date': str(record.expiration_date or '')})
        except Exception as exc: result['whois_note'] = f'WHOIS unavailable: {exc}'
    return result
