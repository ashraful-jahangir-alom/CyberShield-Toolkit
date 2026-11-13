import sys
import traceback
from pathlib import Path

# Add project root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from app import app
except Exception as e:
    print(f"CRITICAL ERROR loading CyberShield: {e}", file=sys.stderr)
    traceback.print_exc()
    raise e
