"""
Legacy entry point: redirect to the new scanner_engine package.

The real implementation lives in backend/services/scanner_engine/
(Nmap-style scan modes, service detection, timing, host discovery).
"""
from backend.services.scanner_engine import (
    __all__,
    is_syn_scan_available,
    resolve_target,
    run_scan,
)

__all__ = ["run_scan", "resolve_target", "is_syn_scan_available"]
