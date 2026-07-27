import socket, ssl
from datetime import datetime


def check_ssl(host):
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=6) as sock:
        with context.wrap_socket(sock, server_hostname=host) as secure:
            cert = secure.getpeercert()
            return {'protocol': secure.version(), 'cipher': secure.cipher()[0], 'subject': dict(x[0] for x in cert.get('subject', [])), 'expires': cert.get('notAfter', ''), 'checked_at': datetime.utcnow().isoformat()}
