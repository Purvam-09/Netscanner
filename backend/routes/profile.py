"""
backend/blueprints/profile.py
-------------------------------
User profile & settings blueprint.

Routes:
    GET   /api/profile/           — get profile
    PATCH /api/profile/           — update username, avatar_color, notify_email
    POST  /api/profile/password   — change password
    GET   /api/profile/stats      — personal scan stats
"""
import logging

from flask import Blueprint, current_app, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from backend.models.db import get_db
from backend.utils.auth_helpers import current_user_id, require_auth, require_csrf
from backend.utils.validators import validate_username

logger = logging.getLogger(__name__)
profile_bp = Blueprint("profile", __name__)


def _db():
    return get_db(current_app.config["DATABASE_PATH"])


# ── Get profile ───────────────────────────────────────────────────────────────

@profile_bp.get("/")
@require_auth
def get_profile():
    user_id = current_user_id()
    with _db() as conn:
        row = conn.execute(
            """SELECT id, username, email, role, avatar_color, notify_email,
                      created_at, last_login
               FROM users WHERE id = ?""",
            (user_id,),
        ).fetchone()

    if not row:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id":           row["id"],
        "username":     row["username"],
        "email":        row["email"],
        "role":         row["role"] or "user",
        "avatar_color": row["avatar_color"] or "#00ff9f",
        "notify_email": bool(row["notify_email"]),
        "created_at":   row["created_at"],
        "last_login":   row["last_login"],
    })


# ── Update profile ────────────────────────────────────────────────────────────

@profile_bp.patch("/")
@require_auth
@require_csrf
def update_profile():
    user_id = current_user_id()
    data    = request.get_json(silent=True) or {}

    updates, params = [], []

    if "username" in data:
        ok, err = validate_username(data["username"])
        if not ok:
            return jsonify({"error": err}), 400
        updates.append("username = ?")
        params.append(data["username"].strip())

    if "avatar_color" in data:
        color = str(data["avatar_color"]).strip()
        if not color.startswith("#") or len(color) not in (4, 7):
            return jsonify({"error": "Invalid avatar color (use #rrggbb)"}), 400
        updates.append("avatar_color = ?")
        params.append(color)

    if "notify_email" in data:
        updates.append("notify_email = ?")
        params.append(1 if data["notify_email"] else 0)

    if not updates:
        return jsonify({"error": "Nothing to update"}), 400

    params.append(user_id)
    try:
        with _db() as conn:
            conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params
            )
            conn.commit()
    except Exception:
        return jsonify({"error": "Username already taken"}), 409

    # Update session username if changed
    if "username" in data:
        session["username"] = data["username"].strip()

    return jsonify({"message": "Profile updated"})


# ── Change password ───────────────────────────────────────────────────────────

@profile_bp.post("/password")
@require_auth
@require_csrf
def change_password():
    user_id = current_user_id()
    data    = request.get_json(silent=True) or {}

    current_pw = data.get("current_password") or ""
    new_pw     = data.get("new_password")     or ""

    if not current_pw or not new_pw:
        return jsonify({"error": "Both current and new password required"}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    with _db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()

    if not row or not check_password_hash(row["password_hash"], current_pw):
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = generate_password_hash(new_pw, method="scrypt")
    with _db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id)
        )
        conn.commit()

    logger.info("Password changed for user %s", user_id)
    return jsonify({"message": "Password updated"})


# ── Personal stats ────────────────────────────────────────────────────────────

@profile_bp.get("/stats")
@require_auth
def personal_stats():
    user_id = current_user_id()
    with _db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)
        ).fetchone()[0]
        completed = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'completed'",
            (user_id,),
        ).fetchone()[0]
        failed = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'failed'",
            (user_id,),
        ).fetchone()[0]
        active = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND status IN ('pending','running')",
            (user_id,),
        ).fetchone()[0]
        scheduled_count = conn.execute(
            "SELECT COUNT(*) FROM scheduled_scans WHERE user_id = ? AND enabled = 1",
            (user_id,),
        ).fetchone()[0]

    return jsonify({
        "total_scans":     total,
        "completed_scans": completed,
        "failed_scans":    failed,
        "active_scans":    active,
        "scheduled_scans": scheduled_count,
    })