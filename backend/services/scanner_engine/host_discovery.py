"""
backend/services/scanner_engine/host_discovery.py
--------------------------------------------------
Pre-scan host discovery: skip hosts that appear down.

Nmap mapping:
  - Default: ping scan / TCP 80,443 / DNS resolve to decide if host is up.
  - -Pn: skip host discovery, assume all hosts are up (we support skip_discovery=True).
"""
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Timeouts for discovery probes (keep short).
DISCOVERY_TIMEOUT = 1.5
COMMON_PORTS = (80, 443, 22, 21, 3389, 8080)  # TCP ports to probe for "host up"


def _tcp_connect_quick(host: str, port: int, timeout: float = DISCOVERY_TIMEOUT) -> bool:
    """Return True if TCP connect succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _dns_resolve(host: str) -> bool:
    """Return True if host resolves (for hostnames). For IPs, consider them valid."""
    if not host or host.replace(".", "").isdigit():
        return True  # Likely an IP; we'll still try TCP
    try:
        socket.gethostbyname(host)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def is_host_up(
    host: str,
    skip_discovery: bool = False,
    timeout: float = DISCOVERY_TIMEOUT,
) -> bool:
    """
    Lightweight check if host is considered "up" before port scanning.

    - If skip_discovery=True (Nmap -Pn): return True (assume up).
    - For hostnames: must resolve via DNS; otherwise considered down.
    - For IPs: always considered up (no ICMP without root; we scan anyway).
    - Optional: try TCP to 80/443/22; if any responds, definitely up.
    """
    if skip_discovery:
        return True

    # Pure IP: assume up (we cannot do ICMP ping without root).
    if host.replace(".", "").replace(" ", "").isdigit():
        return True

    # Hostname: must resolve.
    if not _dns_resolve(host):
        logger.debug("Host discovery: %s did not resolve", host)
        return False
    return True


def filter_live_hosts(
    hosts: list[str],
    skip_discovery: bool = False,
    timeout: float = DISCOVERY_TIMEOUT,
) -> list[str]:
    """
    Return only hosts that pass discovery. If skip_discovery=True, return all hosts unchanged.
    """
    if skip_discovery or not hosts:
        return list(hosts)
    return [h for h in hosts if is_host_up(h, skip_discovery=False, timeout=timeout)]


def probe_hosts_for_ping_sweep(
    hosts: list[str],
    timeout: float = DISCOVERY_TIMEOUT,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> list[str]:
    """
    Ping sweep: probe each host via TCP connect to common ports (80, 443, 22).
    Returns list of hosts that responded on at least one port.
    No root/ICMP required.
    """
    if not hosts:
        return []

    live: list[str] = []
    total = len(hosts)
    done = [0]
    lock = threading.Lock()

    def probe_one(host: str) -> bool:
        if host in ("127.0.0.1", "localhost"):
            return True
        for port in COMMON_PORTS:
            if _tcp_connect_quick(host, port, timeout):
                return True
        return False

    with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as exe:
        futures = {exe.submit(probe_one, h): h for h in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    with lock:
                        live.append(host)
            except Exception:
                pass
            with lock:
                done[0] += 1
                if progress_cb and total > 0:
                    progress_cb(int((done[0] / total) * 100))

    return live
