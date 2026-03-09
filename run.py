import logging
import os
import signal
import sys

from dotenv import load_dotenv

load_dotenv()

from backend import create_app
from backend.extensions import socketio

logger = logging.getLogger("netscanner")
app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", os.environ.get("FLASK_PORT", 5000)))

    def shutdown(sig=None, frame=None):
        logger.info("Shutdown signal received (Ctrl+C). Stopping server…")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info(
        "NetScanner v2.0 — http://%s:%s | Login: http://localhost:%s/login",
        host,
        port,
        port,
    )

    socketio.run(
        app,
        host=host,
        port=port,
        debug=app.config.get("DEBUG", True),
        use_reloader=False,
        log_output=True,
    )