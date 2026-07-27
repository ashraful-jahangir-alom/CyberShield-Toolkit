# CyberShield Toolkit

CyberShield is a Flask-based, authorization-focused cyber security assessment dashboard for education and legitimate security reviews. It deliberately contains no exploitation, brute force, credential attacks, malware, persistence, or privilege-escalation functionality.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. The first run creates SQLite database `database.db` and an administrator account:

- Username: `admin`
- Password: `ChangeMe123!`

Change it immediately by setting `ADMIN_PASSWORD` before first launch. Copy `.env.example` to `.env` only if you use a loader for environment variables; alternatively set environment variables in your host/deployment platform. Set a unique `SECRET_KEY` before production.

## Modules

- Information gathering: DNS, WHOIS, IP/reverse DNS, and certificate observation.
- Network discovery: opt-in ARP discovery on a local authorized CIDR (requires appropriate network privileges).
- Port scanner: a short list of common TCP ports, without service exploitation or aggressive probing.
- Website scanner: redirects, cookies, response headers, HTTPS and baseline security-header scoring.
- Vulnerability assessment: non-invasive findings and remediation guidance based on the website and port observations.
- Password and hashing tools: cryptographically secure generation, entropy estimation, MD5/SHA hashes.
- File encryption: in-memory AES-256-GCM authenticated encryption processing. Files are not saved by the application.
- Reports and logs: SQLite-backed audit trail, CSV export, and downloadable ReportLab PDF summaries.

## Architecture

`app.py` provides protected Flask routes and orchestration. `models/` contains SQLAlchemy entities, `forms/` contains WTForms forms, and `modules/` isolates assessment, encryption, reporting, and utility behavior. Templates use Bootstrap 5 and the custom cyber-themed stylesheet.

## Safety and deployment

Every network scan requires confirmation of authorization in the UI. Use only on targets you own or are explicitly permitted to test. This local development setup uses the in-memory rate-limit backend; production deployments should set a persistent rate-limit storage URI, a strong secret, HTTPS, a production WSGI server, and restrict network egress/scan scope.

## Troubleshooting

- ARP scans commonly require administrator/root permissions and only work on the local network segment.
- WHOIS availability depends on the domain registry and network policy.
- HTTPS checks may fail for hosts with no TLS service, self-signed certificates, or filtered outbound traffic.
- If optional scanning libraries are unavailable, reinstall the requirements in an activated virtual environment.

## License and roadmap

Use for authorized educational and defensive work. Future improvements can include user-managed profiles, a persistent settings table, signed report history, authenticated API integrations, and richer asset inventory controls.
