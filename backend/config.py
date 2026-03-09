"""
backend/config.py
-----------------
Configuration classes for different environments.
Load via app factory: app.config.from_object(config[env])
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")
    DATABASE_PATH = BASE_DIR / os.environ.get("DATABASE_PATH", "database/scanner.db")
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  # True in prod (HTTPS)
    PERMANENT_SESSION_LIFETIME = 86400 * 7  # 7 days

    # Rate limiting
    RATELIMIT_DEFAULT = ["200 per day", "60 per hour"]
    RATELIMIT_STORAGE_URL = "memory://"

    # WebSocket
    SOCKETIO_ASYNC_MODE = "eventlet"
    SOCKETIO_CORS_ALLOWED_ORIGINS = "*"

    # Scanner defaults
    SCAN_MAX_PORTS = 1000
    SCAN_CONNECT_TIMEOUT = 2.0
    SCAN_MAX_WORKERS = 50
    SCAN_RATE_LIMIT = "10 per minute"

    # Log analyzer uploads
    UPLOAD_LOG_DIR = BASE_DIR / "uploads" / "logs"
    MAX_LOG_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    # CVE lookup (NVD public API — no key needed for basic use)
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CVE_CACHE_TTL = 3600  # seconds


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}