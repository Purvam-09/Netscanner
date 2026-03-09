"""
backend/services/log_analyzer.py
--------------------------------
Simple log analysis utilities for the Log Analyzer module.

Function:
    analyze_log(file_path) -> dict
        Analyze a log file on disk and return a summary:
            - total_events: total non-empty lines
            - errors:       lines containing "ERROR"
            - warnings:     lines containing "WARNING"
            - failed_logins: lines containing "failed login"
"""
from __future__ import annotations

from pathlib import Path


def analyze_log(file_path: str | Path) -> dict:
    """
    Analyze the log file at file_path and return summary counts.

    Rules (case-insensitive):
        "ERROR"       -> error event
        "WARNING"     -> warning event
        "failed login" -> failed login event
    """
    path = Path(file_path)
    if not path.is_file():
        return {
            "total_events": 0,
            "errors": 0,
            "warnings": 0,
            "failed_logins": 0,
        }

    total_events = 0
    errors = 0
    warnings = 0
    failed_logins = 0

    # Read as text; tolerate encoding issues.
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            text = line.strip()
            if not text:
                continue
            total_events += 1

            lower = text.lower()
            if "error" in lower:
                errors += 1
            if "warning" in lower:
                warnings += 1
            if "failed login" in lower:
                failed_logins += 1

    return {
        "total_events": total_events,
        "errors": errors,
        "warnings": warnings,
        "failed_logins": failed_logins,
    }

