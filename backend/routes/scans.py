"""
backend/blueprints/scans.py
-----------------------------
Scans blueprint — per-user scan management.

Routes:
    GET    /api/scans              — list user's scans
    POST   /api/scans              — create & enqueue a scan
    GET    /api/scans/<id>         — get full scan detail (with results + CVEs)
    DELETE /api/scans/<id>         — delete scan
    GET    /api/scans/<id>/cves    — get CVE lookup for a completed scan

WebSocket events (flask-socketio):
    join_room  — client joins their user room for live updates
    leave_room — client leaves room
"""
import json
import logging

from flask import Blueprint, current_app, jsonify, request, session
from flask_socketio import join_room, leave_room

from backend.extensions import limiter, socketio
from backend.services.scanner_engine.config import ALLOWED_SCAN_MODES, USER_PORT_MODES
from backend.models.db import get_db
from backend.utils.auth_helpers import current_user_id, require_auth, require_csrf
from backend.utils.validators import parse_port_range, validate_target, validate_target_type

logger = logging.getLogger(__name__)
scans_bp = Blueprint("scans", __name__)

ALLOWED_SCAN_TYPES = ("tcp-connect", "tcp-syn", "udp")


def _db():
    return get_db(current_app.config["DATABASE_PATH"])


# ── WebSocket room management ─────────────────────────────────────────────────

@socketio.on("join_room")
def ws_join(data):
    uid = session.get("user_id")
    if uid:
        join_room(f"user_{uid}")
        logger.debug("User %s joined WS room", uid)


@socketio.on("leave_room")
def ws_leave(data):
    uid = session.get("user_id")
    if uid:
        leave_room(f"user_{uid}")


# ── List scans ────────────────────────────────────────────────────────────────

@scans_bp.get("/")
@require_auth
def list_scans():
    user_id = current_user_id()
    with _db() as conn:
        try:
            rows = conn.execute(
                """SELECT id, target, scan_type, ports, status, progress,
                          created_at, completed_at, duration_seconds, scan_mode
                   FROM scans WHERE user_id = ?
                   ORDER BY created_at DESC""",
                (user_id,),
            ).fetchall()
        except Exception:
            rows = conn.execute(
                """SELECT id, target, scan_type, ports, status, progress,
                          created_at, completed_at, duration_seconds
                   FROM s   cans WHERE user_id = ?
                   ORDER BY created_at DESC""",
                (user_id,),
            ).fetchall()

    scans = [_row_to_summary(r) for r in rows]
    return jsonify({"scans": scans})


# ── Create scan ───────────────────────────────────────────────────────────────

@scans_bp.post("/")
@require_auth
@require_csrf
@limiter.limit("10 per minute")
def create_scan():
    data       = request.get_json(silent=True) or {}
    target     = (data.get("target")     or "").strip()
    scan_type  = (data.get("scan_type")  or "tcp-connect").strip()
    scan_mode  = (data.get("scan_mode")  or "normal").strip()
    port_range = (data.get("port_range") or "1-1000").strip()
    target_type = (data.get("target_type") or "").strip()

    if not target:
        return jsonify({"error": "Target is required"}), 400

    ok, err = validate_target(target)
    if not ok:
        return jsonify({"error": err}), 400

    # Validate target_type matches target
    if target_type:
        ok, err = validate_target_type(target, target_type)
        if not ok:
            return jsonify({"error": err}), 400

    if scan_mode in USER_PORT_MODES:
        try:
            ports = parse_port_range(port_range)
            if not ports:
                return jsonify({"error": "Port range produced no ports"}), 400
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    else:
        port_range = port_range or "1-1000"

    if scan_type not in ALLOWED_SCAN_TYPES:
        scan_type = "tcp-connect"

    if scan_mode not in ALLOWED_SCAN_MODES:
        scan_mode = "normal"

    user_id = current_user_id()
    with _db() as conn:
        try:
            cur = conn.execute(
                """INSERT INTO scans (user_id, target, scan_type, scan_mode, ports, status)
                   VALUES (?, ?, ?, ?, ?, 'pending')""",
                (user_id, target, scan_type, scan_mode, port_range),
            )
        except Exception:
            # Backward compat: DB may not have scan_mode column yet
            cur = conn.execute(
                """INSERT INTO scans (user_id, target, scan_type, ports, status)
                   VALUES (?, ?, ?, ?, 'pending')""",
                (user_id, target, scan_type, port_range),
            )
        conn.commit()
        scan_id = cur.lastrowid

    from backend.services.scan_worker import enqueue_scan
    enqueue_scan(scan_id, current_app._get_current_object())

    logger.info(
        "Scan %s enqueued: user=%s target=%r type=%s mode=%s",
        scan_id, user_id, target, scan_type, scan_mode,
    )
    return jsonify({"id": scan_id, "status": "pending", "message": "Scan enqueued"}), 201


# ── Get scan detail ───────────────────────────────────────────────────────────

@scans_bp.get("/<int:scan_id>")
@require_auth
def get_scan(scan_id: int):
    user_id  = current_user_id()
    is_admin = session.get("role") == "admin"

    with _db() as conn:
        try:
            row = conn.execute(
                """SELECT id, user_id, target, scan_type, ports, status, progress,
                          results_json, error_message, created_at, completed_at, duration_seconds,
                          scan_mode
                   FROM scans WHERE id = ?""",
                (scan_id,),
            ).fetchone()
        except Exception:
            row = conn.execute(
                """SELECT id, user_id, target, scan_type, ports, status, progress,
                          results_json, error_message, created_at, completed_at, duration_seconds
                   FROM scans WHERE id = ?""",
                (scan_id,),
            ).fetchone()

    if not row:
        return jsonify({"error": "Scan not found"}), 404
    if row["user_id"] != user_id and not is_admin:
        return jsonify({"error": "Forbidden"}), 403

    results = None
    if row["results_json"]:
        try:
            results = json.loads(row["results_json"])
        except (TypeError, ValueError):
            pass

    out = {
        "id":               row["id"],
        "target":           row["target"],
        "scan_type":        row["scan_type"],
        "ports":            row["ports"] or "",
        "status":           row["status"],
        "progress":         row["progress"] or 0,
        "created_at":       row["created_at"],
        "completed_at":     row["completed_at"],
        "duration_seconds": row["duration_seconds"],
        "error_message":    row["error_message"],
        "results":          results,
    }
    if "scan_mode" in row.keys():
        out["scan_mode"] = row["scan_mode"] or "normal"
    return jsonify(out)


# ── CVE lookup for a scan ─────────────────────────────────────────────────────

@scans_bp.get("/<int:scan_id>/cves")
@require_auth
def get_scan_cves(scan_id: int):
    user_id  = current_user_id()
    is_admin = session.get("role") == "admin"

    with _db() as conn:
        row = conn.execute(
            "SELECT user_id, results_json, status FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

    if not row:
        return jsonify({"error": "Scan not found"}), 404
    if row["user_id"] != user_id and not is_admin:
        return jsonify({"error": "Forbidden"}), 403
    if row["status"] != "completed":
        return jsonify({"error": "Scan not completed yet"}), 400

    results = {}
    if row["results_json"]:
        try:
            results = json.loads(row["results_json"])
        except (TypeError, ValueError):
            pass

    open_ports = results.get("open_ports", [])
    if not open_ports:
        return jsonify({"cves": {}})

    from backend.services.cve_lookup import lookup_cves_for_ports
    db_path = current_app.config["DATABASE_PATH"]
    cves = lookup_cves_for_ports(open_ports, db_path)
    return jsonify({"cves": cves})


# ── Delete scan ───────────────────────────────────────────────────────────────

@scans_bp.delete("/<int:scan_id>")
@require_auth
@require_csrf
def delete_scan(scan_id: int):
    user_id  = current_user_id()
    is_admin = session.get("role") == "admin"

    with _db() as conn:
        if is_admin:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        else:
            cur = conn.execute(
                "DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)
            )
        conn.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "Scan not found or access denied"}), 404
    return jsonify({"message": "Deleted"})


# ── Helper ────────────────────────────────────────────────────────────────────

def _row_to_summary(r) -> dict:
    summary = {
        "id":               r["id"],
        "target":           r["target"],
        "scan_type":        r["scan_type"],
        "ports":            r["ports"] or "",
        "status":           r["status"],
        "progress":         r["progress"] or 0,
        "date":             (r["created_at"] or "")[:10],
        "created_at":       r["created_at"],
        "completed_at":     r["completed_at"],
        "duration_seconds": r["duration_seconds"],
    }
    if "scan_mode" in r.keys():
        summary["scan_mode"] = r["scan_mode"] or "normal"
    return summary