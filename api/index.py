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
        """WSGI middleware ensuring correct route matching and error visibility on Vercel."""
        def __init__(self, wsgi_app):
            self.wsgi_app = wsgi_app

        def __call__(self, environ, start_response):
            try:
                path = environ.get('PATH_INFO') or ''
                for prefix in ('/api/index.py', '/api/index', '/api'):
                    if path.startswith(prefix):
                        new_path = path[len(prefix):]
                        environ['PATH_INFO'] = new_path if new_path.startswith('/') else '/' + new_path
                        break
                return self.wsgi_app(environ, start_response)
            except Exception as e:
                err = traceback.format_exc()
                print(f"WSGI Handler Error:\n{err}", file=sys.stderr)
                start_response('500 Internal Server Error', [('Content-Type', 'text/plain; charset=utf-8')])
                return [f"Application Error during request:\n\n{err}".encode('utf-8')]

    app.wsgi_app = VercelPathFixer(app.wsgi_app)

except Exception as e:
    startup_err = traceback.format_exc()
    print(f"CRITICAL ERROR loading CyberShield:\n{startup_err}", file=sys.stderr)

    # Fallback WSGI app to display the exact startup crash in the browser instead of generic Vercel 500
    def app(environ, start_response):
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain; charset=utf-8')])
        return [f"CyberShield Startup Error:\n\n{startup_err}".encode('utf-8')]
