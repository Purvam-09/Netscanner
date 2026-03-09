"""
backend/services/scan_worker.py
---------------------------------
Background scan worker.

Flow:
  1. enqueue_scan(scan_id, app) is called from the scans blueprint
  2. A daemon thread is spawned
  3. Thread sets status → running, emits ws progress, then runs engine
  4. On completion: stores results_json, sets status → completed/failed
  5. Emits WebSocket events so the frontend gets live updates
"""
import json
import logging
import threading
import time

logger = logging.getLogger(__name__)


def enqueue_scan(scan_id: int, app) -> None:
    """Spawn a background daemon thread to run the scan."""
    thread = threading.Thread(
        target=_run,
        args=(scan_id, app),
        daemon=True,
        name=f"scan-{scan_id}",
    )
    thread.start()
    logger.info("Scan %s enqueued on thread %s", scan_id, thread.name)


def _run(scan_id: int, app) -> None:
    """
    Main scan execution logic. Runs inside a background thread.
    Needs app context for DB path and SocketIO.
    """
    with app.app_context():
        from backend.extensions import socketio
        from backend.models.db import get_db
        from backend.services.scanner_engine import run_scan

        db_path = app.config["DATABASE_PATH"]
        start   = time.time()

        # ── Fetch scan row ────────────────────────────────────────────────────
        try:
            scan_mode = "normal"
            with get_db(db_path) as conn:
                # Must include user_id so we emit to the correct WS room
                try:
                    row = conn.execute(
                        "SELECT id, user_id, target, scan_type, ports, status, scan_mode FROM scans WHERE id = ?",
                        (scan_id,),
                    ).fetchone()
                    if row and "scan_mode" in row.keys():
                        scan_mode = row["scan_mode"] or "normal"
                except Exception:
                    row = conn.execute(
                        "SELECT id, user_id, target, scan_type, ports, status FROM scans WHERE id = ?",
                        (scan_id,),
                    ).fetchone()
                    scan_mode = "normal"

            if not row or row["status"] != "pending":
                logger.warning("Scan %s not found or not pending, skipping", scan_id)
                return

            user_id = row["user_id"] if "user_id" in row.keys() else None

            # ── Mark as running ───────────────────────────────────────────────
            with get_db(db_path) as conn:
                conn.execute(
                    "UPDATE scans SET status = 'running', progress = 0 WHERE id = ?",
                    (scan_id,),
                )
                conn.commit()

            _emit(socketio, scan_id, user_id, "running", 0)
            # ── Fetch user_id separately (not in above query) ─────────────────
            with get_db(db_path) as conn:
                meta = conn.execute(
                    "SELECT user_id FROM scans WHERE id = ?", (scan_id,)
                ).fetchone()
            user_id = meta["user_id"] if meta else None


            # ── Progress callback ─────────────────────────────────────────────
            _last_pct = [0]

            def progress_cb(pct: int):
                if pct - _last_pct[0] >= 5:  # emit every 5 % change
                    _last_pct[0] = pct
                    with get_db(db_path) as c:
                        c.execute(
                            "UPDATE scans SET progress = ? WHERE id = ?", (pct, scan_id)
                        )
                        c.commit()
                    _emit(socketio, scan_id, user_id, "running", pct)

            # ── Run engine ────────────────────────────────────────────────────
            logger.info("Scan %s starting: target=%r type=%s mode=%s", scan_id, row["target"], row["scan_type"], scan_mode)
            result = run_scan(
                target       = row["target"],
                port_range   = row["ports"] or "1-1000",
                scan_type    = row["scan_type"] or "tcp-connect",
                scan_mode    = scan_mode,
                progress_cb  = progress_cb,
            )

            duration = round(time.time() - start, 2)

            # ── Persist results ───────────────────────────────────────────────
            if result.get("error"):
                with get_db(db_path) as conn:
                    conn.execute(
                        """UPDATE scans SET status='failed', error_message=?,
                           completed_at=datetime('now'), duration_seconds=?, progress=100
                           WHERE id=?""",
                        (result["error"], duration, scan_id),
                    )
                    conn.commit()
                _emit(socketio, scan_id, user_id, "failed", 100,
                      error=result["error"])
                logger.info("Scan %s failed: %s", scan_id, result["error"])
            else:
                results_json = json.dumps(result)
                with get_db(db_path) as conn:
                    conn.execute(
                        """UPDATE scans SET status='completed', results_json=?,
                           error_message=NULL, completed_at=datetime('now'),
                           duration_seconds=?, progress=100 WHERE id=?""",
                        (results_json, duration, scan_id),
                    )
                    conn.commit()
                _emit(socketio, scan_id, user_id, "completed", 100,
                      open_port_count=len(result.get("open_ports", [])))
                logger.info("Scan %s completed in %ss — %s open ports",
                            scan_id, duration, len(result.get("open_ports", [])))

        except Exception as exc:
            duration = round(time.time() - start, 2)
            logger.exception("Scan %s crashed: %s", scan_id, exc)
            try:
                with get_db(db_path) as conn:
                    conn.execute(
                        """UPDATE scans SET status='failed', error_message=?,
                           completed_at=datetime('now'), duration_seconds=?, progress=100
                           WHERE id=?""",
                        (str(exc)[:500], duration, scan_id),
                    )
                    conn.commit()
            except Exception as db_err:
                logger.exception("Could not update scan %s after crash: %s", scan_id, db_err)


def _emit(socketio, scan_id: int, user_id, status: str, progress: int, **extra):
    """Emit a scan_update event to the user's room."""
    payload = {
        "scan_id":  scan_id,
        "status":   status,
        "progress": progress,
        **extra,
    }
    # Emit to room "user_{user_id}" so only that user sees their updates
    room = f"user_{user_id}" if user_id else None
    try:
        if room:
            socketio.emit("scan_update", payload, room=room)
        else:
            socketio.emit("scan_update", payload)
    except Exception as e:
        logger.debug("WebSocket emit failed (client may have disconnected): %s", e)