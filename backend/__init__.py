"""
backend/__init__.py
--------------------
Flask Application Factory.

Usage:
    from backend import create_app
    app = create_app("development")
"""
import logging
import os
from pathlib import Path

from flask import Flask, send_from_directory

from backend.config import config
from backend.extensions import limiter, socketio
from backend.models.db import init_db

BASE_DIR = Path(__file__).resolve().parent.parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("netscanner")


def create_app(env: str = None) -> Flask:
    """
    Create and configure the Flask application.
    Registers all blueprints and extensions.
    """
    env = env or os.environ.get("FLASK_ENV", "development")
    template_dir = BASE_DIR / "backend" / "templates"
    app = Flask(__name__, static_folder=None, template_folder=str(template_dir))
    app.config.from_object(config.get(env, config["default"]))

    # ── Extensions ────────────────────────────────────────────────────────────
    limiter.init_app(app)
    socketio.init_app(
        app,
        async_mode=app.config["SOCKETIO_ASYNC_MODE"],
        cors_allowed_origins=app.config["SOCKETIO_CORS_ALLOWED_ORIGINS"],
    )

    # ── Database ──────────────────────────────────────────────────────────────
    with app.app_context():
        init_db(app.config["DATABASE_PATH"])

    # ── Upload directories ────────────────────────────────────────────────────
    # Ensure log upload directory exists for Log Analyzer module
    upload_logs_dir = app.config.get("UPLOAD_LOG_DIR")
    if upload_logs_dir:
        os.makedirs(upload_logs_dir, exist_ok=True)

    # ── Routes ────────────────────────────────────────────────────────────────
    from backend.routes.auth import auth_bp
    from backend.routes.pages import pages_bp
    from backend.routes.scans import scans_bp
    from backend.routes.host_discovery import host_discovery_bp
    from backend.routes.admin import admin_bp
    from backend.routes.export import export_bp
    from backend.routes.scheduler import scheduler_bp
    from backend.routes.profile import profile_bp
    from backend.routes.logs import logs_bp

    app.register_blueprint(pages_bp)
    app.register_blueprint(host_discovery_bp, url_prefix="/api")
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(export_bp, url_prefix="/api/export")
    app.register_blueprint(scheduler_bp, url_prefix="/api/scheduler")
    app.register_blueprint(profile_bp, url_prefix="/api/profile")
    app.register_blueprint(logs_bp, url_prefix="/api")

    # ── Scheduler startup ─────────────────────────────────────────────────────
    from backend.services.scheduler_service import start_scheduler
    start_scheduler(app)

    # ── Static assets (CSS, JS) ───────────────────────────────────────────────
    frontend_assets = BASE_DIR / "frontend" / "assets"

    @app.route("/assets/<path:path>")
    def static_assets(path):
        return send_from_directory(frontend_assets, path)

    logger.info("NetScanner app created [env=%s]", env)
    return app