import requests
from bs4 import BeautifulSoup
from .security_headers import assess_headers


def scan(host):
    headers_req = {'User-Agent': 'CyberShield-Authorized-Assessment/1.0'}
    if host.startswith(('http://', 'https://')):
        candidates = [host]
    else:
        candidates = [f'https://{host}', f'http://{host}']

    response = None
    last_err = None
    for target_url in candidates:
        try:
            response = requests.get(target_url, timeout=10, allow_redirects=True, headers=headers_req)
            break
        except Exception as exc:
            last_err = exc

    if response is None:
        raise RuntimeError(f"Could not connect to {host}: {last_err}")
    headers = dict(response.headers)
    cookies = [{'name': c.name, 'secure': bool(c.secure), 'http_only': 'httponly' in (c._rest or {})} for c in response.cookies]
    body = response.text[:250000]
    soup = BeautifulSoup(body, 'html.parser')
    missing = assess_headers(headers)
    points = max(0, 100 - len(missing) * 12 - (0 if response.url.startswith('https://') else 20) - sum(5 for c in cookies if not c['secure']))
    return {'url': response.url, 'status_code': response.status_code, 'redirects': len(response.history), 'headers': headers, 'cookies': cookies, 'missing_headers': missing, 'security_score': points, 'title': soup.title.string.strip() if soup.title and soup.title.string else '', 'robots_url': f'{response.url.rstrip("/")}/robots.txt'}
