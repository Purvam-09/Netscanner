"""
backend/utils/auth_helpers.py
------------------------------
Reusable decorators for route protection.

Usage:
    from backend.utils.auth_helpers import require_auth, require_admin, require_csrf

    @app.route("/api/secret")
    @require_auth
    @require_csrf
    def secret():
        ...
"""
import secrets
from functools import wraps

from flask import current_app, make_response, jsonify, redirect, request, session, url_for

from backend.models.db import get_db

# No-cache headers to prevent back-button access after logout
NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


def require_auth(f):
    """Reject request with 401 if no valid session."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapped


def require_login_page(f):
    """
    For page routes: redirect to login if not authenticated.
    Also adds no-cache headers so back button doesn't show cached protected content.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("pages.login"))
        response = f(*args, **kwargs)
        response = make_response(response)
        for key, value in NO_CACHE_HEADERS.items():
            response.headers[key] = value
        return response
    return wrapped


def require_admin(f):
    """Reject request with 403 if user is not admin. Implies require_auth."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        db_path = current_app.config["DATABASE_PATH"]
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT role FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()
        if not row or row["role"] != "admin":
            return jsonify({"error": "Forbidden — admin only"}), 403
        return f(*args, **kwargs)
    return wrapped


def require_csrf(f):
    """
    Validate X-CSRF-Token header against the session token.
    Apply to all state-changing endpoints (POST, PUT, DELETE).
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = request.headers.get("X-CSRF-Token", "")
        session_token = session.get("csrf_token", "")
        if not token or not session_token or not secrets.compare_digest(token, session_token):
            return jsonify({"error": "Invalid or missing CSRF token"}), 403
        return f(*args, **kwargs)
    return wrapped


def current_user_id() -> int | None:
    """Return the current user_id from session, or None."""
    return session.get("user_id")


def current_role() -> str:
    """Return the current user role from session, default 'user'."""
    return session.get("role", "user")