"""
backend/services/scanner_engine/syn_scan.py
--------------------------------------------
TCP SYN scan (-sS). Requires root/admin and Scapy.

Nmap mapping: -sS (half-open scan). Send SYN; SYN-ACK → open, RST → closed.
We do NOT complete the handshake. Only available on Linux with raw sockets;
graceful fallback to connect scan if Scapy missing or not privileged.
"""
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

_SCAPY_AVAILABLE: Optional[bool] = None
_PRIVILEGED: Optional[bool] = None


def _check_scapy() -> bool:
    global _SCAPY_AVAILABLE
    if _SCAPY_AVAILABLE is not None:
        return _SCAPY_AVAILABLE
    try:
        from scapy.all import IP, TCP, sr1  # noqa: F401
        _SCAPY_AVAILABLE = True
    except ImportError:
        _SCAPY_AVAILABLE = False
        logger.info("Scapy not installed; SYN scan unavailable (use tcp-connect)")
    return _SCAPY_AVAILABLE


def _check_privileged() -> bool:
    """True if we can send raw packets (root on Linux)."""
    global _PRIVILEGED
    if _PRIVILEGED is not None:
        return _PRIVILEGED
    try:
        import os
        _PRIVILEGED = os.geteuid() == 0
        if not _PRIVILEGED:
            logger.debug("Not running as root; SYN scan unavailable")
    except AttributeError:
        # Windows: no geteuid
        _PRIVILEGED = False
        logger.debug("SYN scan not supported on this platform (requires Linux + root)")
    return _PRIVILEGED


def is_syn_scan_available() -> bool:
    """True if SYN scan can be used (Scapy + root on Linux)."""
    return _check_scapy() and _check_privileged()


def run_syn_scan(
    hosts: list[str],
    ports: list[int],
    timeout: float = 2.0,
    timing_profile: str = "T3",
    max_workers: int = 50,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> dict[str, list[dict]] | None:
    """
    Run TCP SYN scan. Returns same structure as connect_scan, or None if unavailable.
    Each open port dict has port, protocol, state, banner (empty for SYN).
    """
    if not is_syn_scan_available():
        return None

    try:
        from scapy.all import IP, TCP, sr1
        import threading
    except ImportError:
        return None

    result_by_host: dict[str, list[dict]] = {h: [] for h in hosts}
    total = len(hosts) * len(ports)
    completed = [0]
    lock = threading.Lock()

    def probe_syn(host: str, port: int) -> dict | None:
        try:
            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            ans = sr1(pkt, timeout=timeout, verbose=0)
            if ans is None:
                return None
            if ans.haslayer(TCP):
                flags = ans[TCP].flags
                # 0x12 = SYN-ACK
                if flags == 0x12:
                    # Send RST to close (optional but polite)
                    return {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "banner": "",
                    }
            return None
        except Exception as e:
            logger.debug("SYN probe %s:%s failed: %s", host, port, e)
            return None

    def run_host(host: str):
        for port in ports:
            r = probe_syn(host, port)
            with lock:
                completed[0] += 1
                if progress_cb and total > 0:
                    progress_cb(int((completed[0] / total) * 100))
                if r:
                    result_by_host[host].append(r)

    threads = [threading.Thread(target=run_host, args=(h,)) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for host in result_by_host:
        result_by_host[host].sort(key=lambda x: x["port"])
    return result_by_host
