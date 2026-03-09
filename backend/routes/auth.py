"""
backend/blueprints/auth.py
---------------------------
Authentication blueprint.

Routes:
    POST /api/auth/signup      — create account
    POST /api/auth/login       — sign in, get session + csrf_token
    POST /api/auth/logout      — destroy session
    GET  /api/auth/me          — current user info + fresh csrf_token
"""
import logging
import secrets

from flask import Blueprint, current_app, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from backend.models.db import get_db
from backend.utils.auth_helpers import require_auth
from backend.utils.validators import validate_email, validate_username

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)


def _db():
    return get_db(current_app.config["DATABASE_PATH"])


# ── Sign Up ───────────────────────────────────────────────────────────────────

@auth_bp.post("/signup")
def signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    # Validate
    ok, err = validate_username(username)
    if not ok:
        return jsonify({"error": err}), 400
    ok, err = validate_email(email)
    if not ok:
        return jsonify({"error": err}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    password_hash = generate_password_hash(password, method="scrypt")

    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            conn.commit()
    except Exception:
        return jsonify({"error": "Username or email already exists"}), 409

    logger.info("New user registered: %s", username)
    return jsonify({"message": "Account created. Please log in."}), 201


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    with _db() as conn:
        row = conn.execute(
            "SELECT id, password_hash, role, username FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    # Build session
    session.clear()
    session["user_id"]   = row["id"]
    session["role"]      = row["role"] or "user"
    session["username"]  = row["username"]
    session["csrf_token"] = secrets.token_hex(32)
    session.permanent    = True

    # Update last_login
    with _db() as conn:
        conn.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?", (row["id"],)
        )
        conn.commit()

    logger.info("User logged in: %s (id=%s)", row["username"], row["id"])
    return jsonify({
        "message":    "OK",
        "user_id":    row["id"],
        "username":   row["username"],
        "role":       row["role"] or "user",
        "csrf_token": session["csrf_token"],
    })


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.post("/logout")
def logout():
    session.clear()
    response = jsonify({"message": "Logged out"})
    # Prevent caching of logout response so back button doesn't reuse it
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ── Current User ──────────────────────────────────────────────────────────────

@auth_bp.get("/me")
@require_auth
def me():
    with _db() as conn:
        row = conn.execute(
            "SELECT id, username, email, role, avatar_color, notify_email, created_at, last_login "
            "FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if not row:
        session.clear()
        return jsonify({"authenticated": False}), 401

    # Refresh CSRF token on every /me call so tabs always have a fresh token
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return jsonify({
        "authenticated": True,
        "user_id":       row["id"],
        "username":      row["username"],
        "email":         row["email"],
        "role":          row["role"] or "user",
        "avatar_color":  row["avatar_color"] or "#00ff9f",
        "notify_email":  bool(row["notify_email"]),
        "created_at":    row["created_at"],
        "last_login":    row["last_login"],
        "csrf_token":    session["csrf_token"],
    })