import sys
from pathlib import Path

# Add project root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import Flask app at top level so Vercel entrypoint parser detects it
from app import app


class VercelPathFixer:
    """WSGI middleware ensuring correct route matching on Vercel."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        real_uri = (
            environ.get('HTTP_X_FORWARDED_URI') or
            environ.get('HTTP_X_REAL_PATH') or
            environ.get('HTTP_X_MATCHED_PATH')
        )
        if real_uri:
            clean_path = real_uri.split('?')[0]
            if not clean_path.startswith('/api'):
                environ['PATH_INFO'] = clean_path
        else:
            path = environ.get('PATH_INFO') or ''
            for prefix in ('/api/index.py', '/api/index', '/api'):
                if path.startswith(prefix):
                    new_path = path[len(prefix):]
                    environ['PATH_INFO'] = new_path if new_path.startswith('/') else ('/' + new_path)
                    break
        return self.wsgi_app(environ, start_response)


app.wsgi_app = VercelPathFixer(app.wsgi_app)

# Explicit top-level exports for Vercel
application = app
handler = app
