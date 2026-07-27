from .webscan import scan as web_scan
from .ports import scan as port_scan


def safe_assessment(target):
    web = web_scan(target)
    ports = port_scan(target)
    findings = []
    for item in web['missing_headers']:
        findings.append({'title': f"Missing {item['header']}", 'description': 'The response omits a recommended browser security header.', 'risk': 'MEDIUM', 'evidence': item['header'], 'recommendation': item['recommendation'], 'references': 'OWASP Secure Headers Project'})
    for port in ports:
        if port['risk'] == 'MEDIUM': findings.append({'title': f"Exposed {port['service']} service", 'description': 'A network service is reachable and should be reviewed.', 'risk': 'MEDIUM', 'evidence': f"TCP {port['port']} open", 'recommendation': 'Confirm this service is required, patched, and access-restricted.', 'references': 'CIS Controls'})
    return {'web': web, 'ports': ports, 'findings': findings}
