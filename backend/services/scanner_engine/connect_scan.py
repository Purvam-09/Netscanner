"""
backend/services/scanner_engine/connect_scan.py
-----------------------------------------------
TCP connect scan (-sT). Works without root.

Nmap mapping: -sT (TCP connect scan). We do not use raw sockets;
we complete the full TCP handshake via socket.connect().
"""
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from backend.services.scanner_engine.timing_engine import (
    delay_between_probes,
    should_delay_between_probes,
)

logger = logging.getLogger(__name__)


def _tcp_connect(
    host: str,
    port: int,
    timeout: float,
    grab_banner: bool,
) -> dict | None:
    """
    Single TCP connect probe. Returns port dict on success, None on failure.
    If grab_banner=True, read first bytes for later service detection.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            banner = ""
            if grab_banner:
                try:
                    s.settimeout(1.0)
                    raw = s.recv(256)
                    banner = raw.decode("utf-8", errors="replace").strip()[:120]
                except Exception:
                    pass
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "banner": banner,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def run_connect_scan(
    hosts: list[str],
    ports: list[int],
    timeout: float = 2.0,
    timing_profile: str = "T3",
    max_workers: int = 50,
    grab_banner: bool = True,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> dict[str, list[dict]]:
    """
    Run TCP connect scan on each host for the given ports.
    Uses ThreadPoolExecutor; optional per-probe delay based on timing_profile.

    Returns:
        { "host_ip": [ {"port", "protocol", "state", "banner"}, ... ], ... }
    """
    do_delay = should_delay_between_probes(timing_profile)
    total = len(hosts) * len(ports)
    completed = [0]  # mutable for closure

    result_by_host: dict[str, list[dict]] = {h: [] for h in hosts}

    def probe_one(host: str, port: int) -> Optional[dict]:
        r = _tcp_connect(host, port, timeout, grab_banner=grab_banner)
        if do_delay:
            delay_between_probes(timing_profile)
        return r

    for host in hosts:
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(probe_one, host, p): (host, p) for p in ports}
            for future in as_completed(futures):
                host, port = futures[future]
                completed[0] += 1
                if progress_cb and total > 0:
                    pct = int((completed[0] / total) * 100)
                    progress_cb(pct)
                try:
                    r = future.result()
                    if r:
                        result_by_host[host].append(r)
                except Exception as e:
                    logger.debug("Probe error %s:%s: %s", host, port, e)

    for host in result_by_host:
        result_by_host[host].sort(key=lambda x: x["port"])
    return result_by_host
