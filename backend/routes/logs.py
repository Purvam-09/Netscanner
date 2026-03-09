"""
backend/routes/logs.py
----------------------
Log Analyzer API endpoints.

Route:
    POST /api/logs/analyze  — upload a log file and get summary statistics
"""
from __future__ import annotations

import os
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from backend.extensions import limiter
from backend.services.log_analyzer import analyze_log
from backend.utils.auth_helpers import require_auth, require_csrf

logs_bp = Blueprint("logs", __name__)

ALLOWED_EXTENSIONS = {".log", ".txt", ".json"}


def _allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


@logs_bp.post("/logs/analyze")
@require_auth
@require_csrf
@limiter.limit("10 per minute")
def analyze_logs():
    """
    Accept an uploaded log file, run analysis, and return a JSON summary.

    Constraints:
        - Allowed extensions: .log, .txt, .json
        - Max size: 10 MB (configured via MAX_LOG_FILE_SIZE)
    """
    max_size = int(current_app.config.get("MAX_LOG_FILE_SIZE", 10 * 1024 * 1024))

    # Basic size guard from Content-Length header (may not always be present)
    content_length = request.content_length or 0
    if content_length > max_size:
        return jsonify({"error": "File too large (max 10MB)"}), 413

    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not _allowed_file(file.filename):
        return jsonify({"error": "Unsupported file type"}), 400

    upload_dir = current_app.config.get("UPLOAD_LOG_DIR")
    if not upload_dir:
        return jsonify({"error": "Upload directory not configured"}), 500

    upload_path = Path(upload_dir)
    upload_path.mkdir(parents=True, exist_ok=True)

    from werkzeug.utils import secure_filename

    safe_name = secure_filename(file.filename)
    temp_path = upload_path / safe_name

    # Save to disk, enforcing size limit while streaming.
    total_bytes = 0
    with open(temp_path, "wb") as f:
        while True:
            chunk = file.stream.read(64 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_size:
                f.close()
                temp_path.unlink(missing_ok=True)
                return jsonify({"error": "File too large (max 10MB)"}), 413
            f.write(chunk)

    try:
        summary = analyze_log(temp_path)
    finally:
        # Always delete the uploaded file after processing
        try:
            os.remove(temp_path)
        except OSError:
            pass

    return jsonify(summary)

