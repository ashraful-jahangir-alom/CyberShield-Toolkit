import socket

COMMON_PORTS = {22:'SSH', 80:'HTTP', 443:'HTTPS', 3306:'MySQL', 3389:'RDP', 21:'FTP', 25:'SMTP'}


def scan(host, ports=None):
    ports = ports or list(COMMON_PORTS)
    results = []
    for port in ports:
        try:
            with socket.create_connection((host, int(port)), timeout=0.7):
                results.append({'port': int(port), 'protocol': 'tcp', 'service': COMMON_PORTS.get(int(port), 'unknown'), 'version': 'Not probed', 'state': 'open', 'risk': 'MEDIUM' if int(port) in (21, 3306, 3389) else 'LOW'})
        except (OSError, ValueError): pass
    return results
