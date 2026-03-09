"""
backend/blueprints/admin.py
-----------------------------
Admin-only blueprint.

Routes:
    GET    /api/admin/stats          — dashboard stats
    GET    /api/admin/users          — list all users
    PATCH  /api/admin/users/<id>     — update user role
    GET    /api/admin/scans          — list all scans
    DELETE /api/admin/scans/<id>     — delete any scan
"""
import logging
from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request

from backend.models.db import get_db
from backend.utils.auth_helpers import require_admin, require_csrf

logger = logging.getLogger(__name__)
admin_bp = Blueprint("admin", __name__)


def _db():
    return get_db(current_app.config["DATABASE_PATH"])


# ── Stats ─────────────────────────────────────────────────────────────────────

@admin_bp.get("/stats")
@require_admin
def stats():
    with _db() as conn:
        total_users  = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_scans  = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        active_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status IN ('pending','running')"
        ).fetchone()[0]

        # Daily counts for last 7 days
        daily_counts = []
        for i in range(6, -1, -1):
            day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
            count = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE date(created_at) = ?", (day,)
            ).fetchone()[0]
            daily_counts.append(count)

        # Scan status breakdown
        status_rows = conn.execute(
            "SELECT status, COUNT(*) as cnt FROM scans GROUP BY status"
        ).fetchall()
        status_breakdown = {r["status"]: r["cnt"] for r in status_rows}

        # Top targets
        top_targets = conn.execute(
            """SELECT target, COUNT(*) as cnt FROM scans
               GROUP BY target ORDER BY cnt DESC LIMIT 5"""
        ).fetchall()

    return jsonify({
        "total_users":       total_users,
        "total_scans":       total_scans,
        "active_scans":      active_scans,
        "daily_counts":      daily_counts,
        "status_breakdown":  status_breakdown,
        "top_targets":       [{"target": r["target"], "count": r["cnt"]} for r in top_targets],
    })


# ── Users ─────────────────────────────────────────────────────────────────────

@admin_bp.get("/users")
@require_admin
def list_users():
    with _db() as conn:
        rows = conn.execute(
            """SELECT id, username, email, role, avatar_color, created_at, last_login,
                      (SELECT COUNT(*) FROM scans WHERE user_id = users.id) AS scan_count
               FROM users ORDER BY id"""
        ).fetchall()
    return jsonify({
        "users": [
            {
                "id":           r["id"],
                "username":     r["username"],
                "email":        r["email"],
                "role":         r["role"] or "user",
                "avatar_color": r["avatar_color"],
                "scan_count":   r["scan_count"],
                "created_at":   r["created_at"],
                "last_login":   r["last_login"],
            }
            for r in rows
        ]
    })


@admin_bp.patch("/users/<int:user_id>")
@require_admin
@require_csrf
def update_user(user_id: int):
    data = request.get_json(silent=True) or {}
    new_role = data.get("role", "").strip()
    if new_role not in ("user", "admin"):
        return jsonify({"error": "Role must be 'user' or 'admin'"}), 400

    with _db() as conn:
        cur = conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (new_role, user_id)
        )
        conn.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": f"User {user_id} role updated to {new_role}"})


# ── All Scans ─────────────────────────────────────────────────────────────────

@admin_bp.get("/scans")
@require_admin
def list_scans():
    with _db() as conn:
        rows = conn.execute(
            """SELECT s.id, s.user_id, u.username, s.target, s.scan_type,
                      s.ports, s.status, s.progress, s.created_at, s.completed_at,
                      s.duration_seconds
               FROM scans s LEFT JOIN users u ON u.id = s.user_id
               ORDER BY s.created_at DESC
               LIMIT 200""",
        ).fetchall()

    return jsonify({
        "scans": [
            {
                "id":               r["id"],
                "user_id":          r["user_id"],
                "username":         r["username"] or "—",
                "target":           r["target"],
                "scan_type":        r["scan_type"],
                "ports":            r["ports"] or "",
                "status":           r["status"],
                "progress":         r["progress"] or 0,
                "created_at":       r["created_at"],
                "completed_at":     r["completed_at"],
                "duration_seconds": r["duration_seconds"],
            }
            for r in rows
        ]
    })


@admin_bp.delete("/scans/<int:scan_id>")
@require_admin
@require_csrf
def delete_scan(scan_id: int):
    with _db() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"message": "Deleted"})