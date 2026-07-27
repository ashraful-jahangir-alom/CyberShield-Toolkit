RECOMMENDED = {
    'content-security-policy': 'Set a restrictive Content-Security-Policy.',
    'strict-transport-security': 'Enable HSTS for HTTPS sites.',
    'x-content-type-options': 'Set X-Content-Type-Options: nosniff.',
    'x-frame-options': 'Set X-Frame-Options or frame-ancestors in CSP.',
    'referrer-policy': 'Set a conservative Referrer-Policy.',
    'permissions-policy': 'Set Permissions-Policy for browser features.',
}


def assess_headers(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    missing = [{'header': key, 'recommendation': value} for key, value in RECOMMENDED.items() if key not in lower]
    return missing
