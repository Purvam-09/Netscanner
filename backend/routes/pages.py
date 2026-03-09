"""
backend/blueprints/pages.py
----------------------------
Page routes (clean URLs, no .html).
Serves HTML from backend/templates/ with auth protection and no-cache on protected pages.
"""
from flask import Blueprint, render_template

from backend.utils.auth_helpers import require_login_page

pages_bp = Blueprint("pages", __name__)


@pages_bp.get("/")
@require_login_page
def index():
    return render_template("index.html")


@pages_bp.get("/results")
@require_login_page
def results():
    return render_template("results.html")


@pages_bp.get("/discovery")
@require_login_page
def discovery():
    return render_template("discovery.html")


@pages_bp.get("/scan")
@require_login_page
def scan():
    return render_template("scan.html")


@pages_bp.get("/scan/port")
@require_login_page
def scan_port():
    """Port Scan page (same template as /scan); use for prefill from Host Discovery."""
    return render_template("scan.html")


@pages_bp.get("/network-radar")
@require_login_page
def network_radar():
    """Network Radar visualization (latest Host Discovery alive hosts)."""
    return render_template("network_radar.html")


@pages_bp.get("/log-analyzer")
@require_login_page
def log_analyzer():
    """Log Analyzer page — upload and analyze log files."""
    return render_template("log_analyzer.html")


@pages_bp.get("/admin")
@require_login_page
def admin():
    return render_template("admin.html")


@pages_bp.get("/profile")
@require_login_page
def profile():
    return render_template("profile.html")


@pages_bp.get("/scheduler")
@require_login_page
def scheduler():
    return render_template("scheduler.html")


@pages_bp.get("/login")
def login():
    return render_template("auth/login.html")


@pages_bp.get("/signup")
def signup():
    return render_template("auth/signup.html")
