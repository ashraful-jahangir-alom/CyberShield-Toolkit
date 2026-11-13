import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# On Vercel, the root filesystem is read-only except /tmp
IS_VERCEL = bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV"))
DATA_DIR = Path("/tmp") if IS_VERCEL else BASE_DIR


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-development-secret")
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATA_DIR / 'database.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024
    UPLOAD_FOLDER = DATA_DIR / "uploads"
    REPORT_FOLDER = DATA_DIR / "reports"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_TIME_LIMIT = 3600
