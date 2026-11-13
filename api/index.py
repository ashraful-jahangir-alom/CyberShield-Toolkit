import sys
import traceback
from pathlib import Path

# Add project root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from app import app

    class VercelPathFixer:
        """WSGI middleware ensuring correct route matching on Vercel."""
        def __init__(self, wsgi_app):
            self.wsgi_app = wsgi_app

        def __call__(self, environ, start_response):
            path = environ.get('PATH_INFO', '')
            for prefix in ('/api/index.py', '/api/index', '/api'):
                if path.startswith(prefix):
                    new_path = path[len(prefix):]
                    environ['PATH_INFO'] = new_path if new_path.startswith('/') else '/' + new_path
                    break
            return self.wsgi_app(environ, start_response)

    app.wsgi_app = VercelPathFixer(app.wsgi_app)

except Exception as e:
    print(f"CRITICAL ERROR loading CyberShield: {e}", file=sys.stderr)
    traceback.print_exc()
    raise e
