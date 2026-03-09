"""
backend/blueprints/scheduler.py
---------------------------------
Scheduled scans blueprint.

Routes:
    GET    /api/scheduler/          — list user's scheduled scans
    POST   /api/scheduler/          — create scheduled scan
    PATCH  /api/scheduler/<id>      — update (enable/disable/change cron)
    DELETE /api/scheduler/<id>      — delete scheduled scan
"""
import logging

from flask import Blueprint, current_app, jsonify, request

from backend.models.db import get_db
from backend.utils.auth_helpers import current_user_id, require_auth, require_csrf
from backend.utils.validators import parse_port_range, validate_cron, validate_target

logger = logging.getLogger(__name__)
scheduler_bp = Blueprint("scheduler", __name__)


def _db():
    return get_db(current_app.config["DATABASE_PATH"])


# ── List ──────────────────────────────────────────────────────────────────────

@scheduler_bp.get("/")
@require_auth
def list_scheduled():
    user_id = current_user_id()
    with _db() as conn:
        rows = conn.execute(
            """SELECT id, target, scan_type, ports, cron_expr, label,
                      enabled, last_run, next_run, created_at
               FROM scheduled_scans WHERE user_id = ?
               ORDER BY created_at DESC""",
            (user_id,),
        ).fetchall()
    return jsonify({
        "scheduled": [
            {
                "id":         r["id"],
                "target":     r["target"],
                "scan_type":  r["scan_type"],
                "ports":      r["ports"],
                "cron_expr":  r["cron_expr"],
                "label":      r["label"] or "",
                "enabled":    bool(r["enabled"]),
                "last_run":   r["last_run"],
                "next_run":   r["next_run"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    })


# ── Create ────────────────────────────────────────────────────────────────────

@scheduler_bp.post("/")
@require_auth
@require_csrf
def create_scheduled():
    data       = request.get_json(silent=True) or {}
    target     = (data.get("target")     or "").strip()
    scan_type  = (data.get("scan_type")  or "tcp-connect").strip()
    port_range = (data.get("port_range") or "1-1000").strip()
    cron_expr  = (data.get("cron_expr")  or "").strip()
    label      = (data.get("label")      or "").strip()[:100]

    ok, err = validate_target(target)
    if not ok:
        return jsonify({"error": err}), 400

    ok, err = validate_cron(cron_expr)
    if not ok:
        return jsonify({"error": err}), 400

    try:
        parse_port_range(port_range)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    user_id = current_user_id()
    with _db() as conn:
        cur = conn.execute(
            """INSERT INTO scheduled_scans
               (user_id, target, scan_type, ports, cron_expr, label, enabled)
               VALUES (?, ?, ?, ?, ?, ?, 1)""",
            (user_id, target, scan_type, port_range, cron_expr, label),
        )
        conn.commit()
        scheduled_id = cur.lastrowid

    # Register with APScheduler
    from backend.services.scheduler_service import add_scheduled_job
    add_scheduled_job(scheduled_id, cron_expr)

    logger.info("Scheduled scan %s created for user %s", scheduled_id, user_id)
    return jsonify({"id": scheduled_id, "message": "Scheduled scan created"}), 201


# ── Update ────────────────────────────────────────────────────────────────────

@scheduler_bp.patch("/<int:sched_id>")
@require_auth
@require_csrf
def update_scheduled(sched_id: int):
    user_id = current_user_id()
    data    = request.get_json(silent=True) or {}

    # Check ownership
    with _db() as conn:
        row = conn.execute(
            "SELECT id FROM scheduled_scans WHERE id = ? AND user_id = ?",
            (sched_id, user_id),
        ).fetchone()
    if not row:
        return jsonify({"error": "Not found or access denied"}), 404

    # Build update fields
    updates, params = [], []
    if "enabled" in data:
        updates.append("enabled = ?")
        params.append(1 if data["enabled"] else 0)
    if "cron_expr" in data:
        ok, err = validate_cron(data["cron_expr"])
        if not ok:
            return jsonify({"error": err}), 400
        updates.append("cron_expr = ?")
        params.append(data["cron_expr"].strip())
    if "label" in data:
        updates.append("label = ?")
        params.append(str(data["label"])[:100])

    if not updates:
        return jsonify({"error": "Nothing to update"}), 400

    params.append(sched_id)
    with _db() as conn:
        conn.execute(
            f"UPDATE scheduled_scans SET {', '.join(updates)} WHERE id = ?", params
        )
        conn.commit()
        new_row = conn.execute(
            "SELECT cron_expr, enabled FROM scheduled_scans WHERE id = ?", (sched_id,)
        ).fetchone()

    # Re-register job if cron changed or enabled toggled
    from backend.services.scheduler_service import add_scheduled_job, remove_scheduled_job
    if new_row["enabled"]:
        add_scheduled_job(sched_id, new_row["cron_expr"])
    else:
        remove_scheduled_job(sched_id)

    return jsonify({"message": "Updated"})


# ── Delete ────────────────────────────────────────────────────────────────────

@scheduler_bp.delete("/<int:sched_id>")
@require_auth
@require_csrf
def delete_scheduled(sched_id: int):
    user_id = current_user_id()
    with _db() as conn:
        cur = conn.execute(
            "DELETE FROM scheduled_scans WHERE id = ? AND user_id = ?",
            (sched_id, user_id),
        )
        conn.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "Not found or access denied"}), 404

    from backend.services.scheduler_service import remove_scheduled_job
    remove_scheduled_job(sched_id)

    return jsonify({"message": "Deleted"})