"""
backend/blueprints/host_discovery.py
-------------------------------------
Host Discovery API — find live hosts via ping sweep.
Stores each discovery run as a scan record so it appears on the Results page.

Route:
    POST /scan/discovery  — run discovery scan (start_ip+end_ip OR cidr), save to DB, return results
"""
import json
import logging
import time

from flask import Blueprint, current_app, jsonify, request

from backend.extensions import limiter
from backend.models.db import get_db
from backend.services.discovery_ping import run_discovery
from backend.utils.auth_helpers import require_auth, require_csrf, current_user_id

logger = logging.getLogger(__name__)

host_discovery_bp = Blueprint("host_discovery", __name__)

def _alive_hosts_from_results_json(results_json: str) -> list[dict]:
    """Parse a host-discovery scan results_json and return alive hosts list."""
    if not results_json:
        return []
    try:
        payload = json.loads(results_json)
    except (TypeError, ValueError):
        return []
    discovery_results = payload.get("discovery_results") or []
    out = []
    for r in discovery_results:
        if not isinstance(r, dict):
            continue
        if r.get("status") != "alive":
            continue
        out.append(
            {
                "ip": r.get("ip") or "",
                "hostname": r.get("hostname") or "",
                "status": "alive",
            }
        )
    return [h for h in out if h.get("ip")]


@host_discovery_bp.post("/scan/discovery")
@require_auth
@require_csrf
@limiter.limit("10 per minute")
def discovery_scan():
    """
    Run host discovery scan, store in scans table, return results.
    JSON body: { start_ip, end_ip } OR { cidr }
    Returns: { results: [...], scan_id: N } so UI can show table and Results page gets the record.
    """
    data = request.get_json(silent=True) or {}
    start_ip = (data.get("start_ip") or "").strip()
    end_ip = (data.get("end_ip") or "").strip()
    cidr = (data.get("cidr") or "").strip()

    if cidr:
        if start_ip or end_ip:
            return jsonify({"error": "Use either CIDR or Start/End IP, not both"}), 400
        try:
            import ipaddress
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            return jsonify({"error": f"Invalid CIDR: {e}"}), 400
        target = cidr
    elif start_ip and end_ip:
        try:
            import ipaddress
            ipaddress.ip_address(start_ip)
            ipaddress.ip_address(end_ip)
        except ValueError as e:
            return jsonify({"error": f"Invalid IP range: {e}"}), 400
        target = f"{start_ip}-{end_ip}"
    else:
        return jsonify({
            "error": "Provide either CIDR (e.g. 192.168.1.0/24) or Start IP + End IP",
        }), 400

    t0 = time.perf_counter()
    results = run_discovery(start_ip=start_ip or None, end_ip=end_ip or None, cidr=cidr or None)
    duration_seconds = round(time.perf_counter() - t0, 2)

    if not results:
        return jsonify({"error": "No IPs generated. Check your range or CIDR."}), 400

    # Build payload for scans.results_json (same shape as ping sweep for modal)
    hosts_up = [r["ip"] for r in results if r.get("status") == "alive"]
    total = len(results)
    hosts_down_count = total - len(hosts_up)
    results_payload = {
        "hosts_up": hosts_up,
        "hosts_down_count": hosts_down_count,
        "total_hosts_scanned": total,
        "discovery_results": results,
    }

    user_id = current_user_id()
    db_path = current_app.config["DATABASE_PATH"]

    with get_db(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO scans (user_id, target, scan_type, ports, status, progress, results_json, completed_at, duration_seconds)
               VALUES (?, ?, 'host-discovery', 'N/A', 'completed', 100, ?, datetime('now'), ?)""",
            (user_id, target, json.dumps(results_payload), duration_seconds),
        )
        conn.commit()
        scan_id = cur.lastrowid

    logger.info("Host discovery saved: scan_id=%s target=%s hosts_up=%d total=%d", scan_id, target, len(hosts_up), total)
    return jsonify({"results": results, "scan_id": scan_id})


@host_discovery_bp.post("/scan/port/from-discovery")
@require_auth
@require_csrf
@limiter.limit("30 per minute")
def port_scan_from_discovery():
    """
    Accept selected hosts from Host Discovery and return redirect URL for Port Scan page.
    Body: { "targets": ["192.168.1.10", "192.168.1.15"] }
    Returns: { "redirect_url": "/scan/port?import=..." }
    """
    data = request.get_json(silent=True) or {}
    targets = data.get("targets")
    if not targets or not isinstance(targets, list):
        return jsonify({"error": "targets array is required"}), 400
    ips = [str(t).strip() for t in targets if str(t).strip()]
    if not ips:
        return jsonify({"error": "At least one target IP is required"}), 400
    # Limit to avoid huge URLs
    ips = ips[:100]
    import_param = ",".join(ips)
    from urllib.parse import quote
    redirect_url = "/scan/port?import=" + quote(import_param, safe=",")
    return jsonify({"redirect_url": redirect_url})


@host_discovery_bp.get("/network-map")
@require_auth
@limiter.limit("60 per minute")
def network_map():
    """
    Return alive hosts from the latest Host Discovery scan for the current user.

    Response JSON:
        [
          {"ip":"192.168.1.1","hostname":"router","status":"alive"},
          {"ip":"192.168.1.10","hostname":"laptop","status":"alive"}
        ]
    """
    user_id = current_user_id()
    db_path = current_app.config["DATABASE_PATH"]

    with get_db(db_path) as conn:
        row = conn.execute(
            """SELECT results_json
               FROM scans
               WHERE user_id = ? AND scan_type = 'host-discovery' AND status = 'completed'
               ORDER BY created_at DESC
               LIMIT 1""",
            (user_id,),
        ).fetchone()

    if not row or not row["results_json"]:
        return jsonify([])

    return jsonify(_alive_hosts_from_results_json(row["results_json"]))


@host_discovery_bp.get("/network-map/<int:scan_id>")
@require_auth
@limiter.limit("60 per minute")
def network_map_for_scan(scan_id: int):
    """
    Return alive hosts for a specific Host Discovery scan_id (must belong to current user).

    Response JSON:
        [{"ip":"...","hostname":"...","status":"alive"}, ...]
    """
    user_id = current_user_id()
    db_path = current_app.config["DATABASE_PATH"]

    with get_db(db_path) as conn:
        row = conn.execute(
            """SELECT results_json
               FROM scans
               WHERE id = ? AND user_id = ? AND scan_type = 'host-discovery' AND status = 'completed'
               LIMIT 1""",
            (scan_id, user_id),
        ).fetchone()

    if not row or not row["results_json"]:
        return jsonify([]), 404

    return jsonify(_alive_hosts_from_results_json(row["results_json"]))


@host_discovery_bp.get("/discovery-scans")
@require_auth
@limiter.limit("60 per minute")
def list_discovery_scans():
    """
    List Host Discovery scans for the current user (newest first).

    Response JSON:
        [
          {"scan_id": 18, "target": "192.168.1.0/24", "alive_hosts": 7, "date": "2026-03-09"},
          ...
        ]
    """
    user_id = current_user_id()
    db_path = current_app.config["DATABASE_PATH"]

    with get_db(db_path) as conn:
        rows = conn.execute(
            """SELECT id, target, created_at, results_json
               FROM scans
               WHERE user_id = ? AND scan_type = 'host-discovery' AND status = 'completed'
               ORDER BY created_at DESC""",
            (user_id,),
        ).fetchall()

    out = []
    for r in rows:
        alive = _alive_hosts_from_results_json(r["results_json"] or "")
        out.append(
            {
                "scan_id": r["id"],
                "target": r["target"] or "",
                "alive_hosts": len(alive),
                "date": (r["created_at"] or "")[:10],
            }
        )

    return jsonify(out)
