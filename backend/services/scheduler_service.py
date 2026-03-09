"""
backend/services/scheduler_service.py
----------------------------------------
Manages scheduled (recurring) scans using APScheduler.

Each scheduled_scan row has a cron_expr (5-field cron string).
On app startup, we load all enabled scheduled scans and register them.
When a scheduled job fires, it inserts a new scan row and enqueues it.
"""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_scheduler = None   # APScheduler instance, set in start_scheduler()
_app       = None   # Flask app, set in start_scheduler()


def start_scheduler(app) -> None:
    """
    Initialise APScheduler and register all enabled scheduled scans.
    Called once from the app factory.
    """
    global _scheduler, _app
    _app = app

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        logger.warning("APScheduler not installed — scheduled scans disabled")
        return

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.start()
    logger.info("APScheduler started")

    # Load existing scheduled scans
    with app.app_context():
        _reload_all_jobs()


def _reload_all_jobs() -> None:
    """Clear all jobs and re-register from DB."""
    if _scheduler is None:
        return
    _scheduler.remove_all_jobs()

    from backend.models.db import get_db
    db_path = _app.config["DATABASE_PATH"]

    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT id, cron_expr FROM scheduled_scans WHERE enabled = 1"
        ).fetchall()

    for row in rows:
        _register_job(row["id"], row["cron_expr"])
    logger.info("Registered %d scheduled scan jobs", len(rows))


def _register_job(scheduled_id: int, cron_expr: str) -> None:
    """Register a single APScheduler cron job for a scheduled_scan row."""
    if _scheduler is None:
        return
    try:
        from apscheduler.triggers.cron import CronTrigger
        parts = cron_expr.strip().split()
        trigger = CronTrigger(
            minute=parts[0], hour=parts[1], day=parts[2],
            month=parts[3], day_of_week=parts[4],
        )
        _scheduler.add_job(
            func=_fire_scheduled_scan,
            trigger=trigger,
            args=[scheduled_id],
            id=f"sched_{scheduled_id}",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning("Failed to register job for scheduled_scan %s: %s", scheduled_id, e)


def _fire_scheduled_scan(scheduled_id: int) -> None:
    """
    Called by APScheduler at cron time.
    Creates a new scan row and enqueues it.
    """
    if _app is None:
        return
    with _app.app_context():
        from backend.models.db import get_db
        from backend.services.scan_worker import enqueue_scan

        db_path = _app.config["DATABASE_PATH"]
        try:
            with get_db(db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM scheduled_scans WHERE id = ? AND enabled = 1",
                    (scheduled_id,),
                ).fetchone()

            if not row:
                return

            # Create a new scan (scan_mode=normal for scheduled; DB default handles legacy)
            with get_db(db_path) as conn:
                try:
                    cur = conn.execute(
                        """INSERT INTO scans (user_id, target, scan_type, scan_mode, ports, status)
                           VALUES (?, ?, ?, 'normal', ?, 'pending')""",
                        (row["user_id"], row["target"], row["scan_type"], row["ports"]),
                    )
                except Exception:
                    cur = conn.execute(
                        """INSERT INTO scans (user_id, target, scan_type, ports, status)
                           VALUES (?, ?, ?, ?, 'pending')""",
                        (row["user_id"], row["target"], row["scan_type"], row["ports"]),
                    )
                scan_id = cur.lastrowid
                conn.execute(
                    "UPDATE scheduled_scans SET last_run = datetime('now') WHERE id = ?",
                    (scheduled_id,),
                )
                conn.commit()

            enqueue_scan(scan_id, _app)
            logger.info("Scheduled scan fired: sched_id=%s → scan_id=%s", scheduled_id, scan_id)
        except Exception as e:
            logger.exception("Scheduled scan %s failed to fire: %s", scheduled_id, e)


# ── Public API for blueprint ──────────────────────────────────────────────────

def add_scheduled_job(scheduled_id: int, cron_expr: str) -> None:
    _register_job(scheduled_id, cron_expr)


def remove_scheduled_job(scheduled_id: int) -> None:
    if _scheduler is None:
        return
    try:
        _scheduler.remove_job(f"sched_{scheduled_id}")
    except Exception:
        pass


def reload_jobs() -> None:
    _reload_all_jobs()