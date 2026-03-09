"""
backend/blueprints/export.py
------------------------------
Export blueprint.

Routes:
    GET /api/export/scans/<id>/csv   — download scan as CSV
    GET /api/export/scans/<id>/pdf   — download scan as PDF
    GET /api/export/scans/csv        — download ALL user scans as CSV
"""
import json
import logging

from flask import Blueprint, Response, current_app, jsonify, session

from backend.models.db import get_db
from backend.utils.auth_helpers import current_user_id, require_auth

logger = logging.getLogger(__name__)
export_bp = Blueprint("export", __name__)


def _db():
    return get_db(current_app.config["DATABASE_PATH"])


def _get_scan_for_user(scan_id: int) -> dict | None:
    user_id  = current_user_id()
    is_admin = session.get("role") == "admin"

    with _db() as conn:
        row = conn.execute(
            """SELECT id, user_id, target, scan_type, ports, status,
                      results_json, error_message, created_at, completed_at, duration_seconds
               FROM scans WHERE id = ?""",
            (scan_id,),
        ).fetchone()

    if not row:
        return None
    if row["user_id"] != user_id and not is_admin:
        return None

    results = None
    if row["results_json"]:
        try:
            results = json.loads(row["results_json"])
        except (TypeError, ValueError):
            pass

    return {
        "id":               row["id"],
        "target":           row["target"],
        "scan_type":        row["scan_type"],
        "ports":            row["ports"],
        "status":           row["status"],
        "error_message":    row["error_message"],
        "created_at":       row["created_at"],
        "completed_at":     row["completed_at"],
        "duration_seconds": row["duration_seconds"],
        "_results":         results,
    }


# ── Single scan CSV ───────────────────────────────────────────────────────────

@export_bp.get("/scans/<int:scan_id>/csv")
@require_auth
def export_scan_csv(scan_id: int):
    scan = _get_scan_for_user(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found or access denied"}), 404

    from backend.services.export_service import generate_csv
    csv_bytes = generate_csv(scan, scan.pop("_results", None))

    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"',
            "Content-Length": str(len(csv_bytes)),
        },
    )


# ── Single scan PDF ───────────────────────────────────────────────────────────

@export_bp.get("/scans/<int:scan_id>/pdf")
@require_auth
def export_scan_pdf(scan_id: int):
    scan = _get_scan_for_user(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found or access denied"}), 404

    try:
        from backend.services.export_service import generate_pdf
        results = scan.pop("_results", None)
        pdf_bytes = generate_pdf(scan, results)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan_{scan_id}.pdf"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


# ── All user scans CSV ────────────────────────────────────────────────────────

@export_bp.get("/scans/csv")
@require_auth
def export_all_csv():
    user_id = current_user_id()
    with _db() as conn:
        rows = conn.execute(
            """SELECT id, target, scan_type, ports, status, results_json,
                      error_message, created_at, completed_at, duration_seconds
               FROM scans WHERE user_id = ? ORDER BY created_at DESC""",
            (user_id,),
        ).fetchall()

    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "scan_id", "target", "scan_type", "ports", "status",
        "port", "protocol", "service", "version", "banner", "state",
        "duration_s", "completed_at",
    ])

    for row in rows:
        results = {}
        if row["results_json"]:
            try:
                results = json.loads(row["results_json"])
            except (TypeError, ValueError):
                pass
        scan_type = row["scan_type"] or "tcp-connect"
        if scan_type in ("ping", "host-discovery"):
            hosts_up = results.get("hosts_up", [])
            for h in hosts_up:
                writer.writerow([
                    row["id"], row["target"], row["scan_type"], "N/A",
                    row["status"], h, "host", "up", "", "", "alive",
                    row["duration_seconds"] or "", row["completed_at"] or "",
                ])
            if not hosts_up:
                writer.writerow([
                    row["id"], row["target"], row["scan_type"], "N/A",
                    row["status"], "", "host", "", "", "", "no hosts up",
                    row["duration_seconds"] or "", row["completed_at"] or "",
                ])
        else:
            open_ports = results.get("open_ports", [])
            if not open_ports:
                writer.writerow([
                    row["id"], row["target"], row["scan_type"], row["ports"],
                    row["status"], "", "", "", "", "", "",
                    row["duration_seconds"] or "", row["completed_at"] or "",
                ])
            else:
                for p in open_ports:
                    writer.writerow([
                        row["id"], row["target"], row["scan_type"], row["ports"],
                        row["status"],
                        p.get("port", ""), p.get("protocol", "tcp"),
                        p.get("service", ""), p.get("version", ""), p.get("banner", ""),
                        p.get("state", "open"),
                        row["duration_seconds"] or "", row["completed_at"] or "",
                    ])

    csv_bytes = buf.getvalue().encode("utf-8")
    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="all_scans.csv"',
            "Content-Length": str(len(csv_bytes)),
        },
    )