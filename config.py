import os
import tempfile
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def is_serverless():
    """Detect if running in Vercel, AWS Lambda, or a read-only environment."""
    serverless_envs = (
        "VERCEL",
        "VERCEL_ENV",
        "VERCEL_REGION",
        "AWS_LAMBDA_FUNCTION_NAME",
        "LAMBDA_TASK_ROOT",
        "NOW_REGION",
    )
    if any(os.getenv(k) for k in serverless_envs):
        return True
    try:
        test = BASE_DIR / ".write_test"
        test.touch()
        test.unlink()
        return False
    except Exception:
        return True


if is_serverless():
    DATA_DIR = Path("/tmp") if os.name != "nt" else Path(tempfile.gettempdir())
    SQLALCHEMY_DATABASE_URI = "sqlite:////tmp/database.db" if os.name != "nt" else f"sqlite:///{(DATA_DIR / 'database.db').as_posix()}"
else:
    DATA_DIR = BASE_DIR
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'database.db'}"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-development-secret")
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024
    UPLOAD_FOLDER = DATA_DIR / "uploads"
    REPORT_FOLDER = DATA_DIR / "reports"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_TIME_LIMIT = 3600
