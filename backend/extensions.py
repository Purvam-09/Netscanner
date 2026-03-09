"""
backend/extensions.py
----------------------
All Flask extension instances live here.
Import from here to avoid circular imports.

Usage:
    from backend.extensions import socketio, limiter
"""
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

socketio = SocketIO()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)