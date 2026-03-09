"""
backend/services/scanner_engine/__init__.py
---------------------------------------------
Nmap-inspired custom scanning engine (no Nmap binary).

Scan types:
  - tcp-connect   : TCP connect (-sT), default, works without root
  - tcp-syn       : SYN scan (-sS) when Scapy + root available; else connect
  - udp           : Basic UDP probe
  - ping          : Host discovery only (no raw ICMP; uses TCP/DNS checks)

Scan modes (Nmap-style):
  - fast          : Top 100 ports (--top-ports 100)
  - top_1000      : Top 1000 ports
  - full          : All ports 1-65535 (-p-)
  - stealth_connect : Connect with T2 timing, no banner (-sT -T2)
  - normal        : Current behavior; use port_range

Results schema includes: scan_type, scan_mode, hosts[{ ip, ports[{ port, state, service, version }] }],
plus flattened open_ports for backward compatibility.
"""
import ipaddress
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from backend.services.scanner_engine import connect_scan, host_discovery, service_detection, timing_engine
from backend.services.scanner_engine.config import (
    ALLOWED_SCAN_MODES,
    SCAN_MODE_CONFIG,
    TOP_100_PORTS,
    USER_PORT_MODES,
    get_full_port_list,
    get_top_1000_ports,
)
from backend.services.scanner_engine.results import SERVICE_NAMES, build_hosts_and_open_ports
from backend.services.scanner_engine.syn_scan import is_syn_scan_available, run_syn_scan

logger = logging.getLogger(__name__)


def _resolve_single_target(t: str) -> list[str]:
    """Resolve one target (IP, CIDR, or hostname) to list of IPv4 strings."""
    t = t.strip()
    if not t:
        return []
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            if len(hosts) > 256:
                logger.warning("CIDR too large, capping at 256 hosts")
                hosts = hosts[:256]
            return hosts
        except ValueError:
            return []
    if re.match(r"^[\d.]+$", t):
        try:
            ipaddress.ip_address(t)
            return [t]
        except ValueError:
            return []
    try:
        return [socket.gethostbyname(t)]
    except (socket.gaierror, socket.timeout) as e:
        logger.warning("DNS resolution failed for %s: %s", t, e)
        return []


def resolve_target(target: str) -> list[str]:
    """
    Return list of IPv4 strings for target.
    Supports: single IP, CIDR, hostname, or comma/newline-separated list.
    """
    t = target.strip()
    if not t:
        return []
    parts = re.split(r"[\s,]+", t)
    seen: set[str] = set()
    result: list[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        for ip in _resolve_single_target(part):
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
    return result


def _get_ports_for_mode(
    scan_mode: str,
    port_range: str,
    parse_port_range_fn,
    max_ports_user: int = 1000,
) -> list[int]:
    """
    Resolve port list from scan_mode. Single source of truth.
    - fast, top_1000, full: predefined ports ONLY; user port_range is IGNORED.
    - normal, stealth_connect: user-entered port range ONLY; no predefined merge.
    """
    if scan_mode in USER_PORT_MODES:
        return parse_port_range_fn(port_range or "1-1000", max_ports=max_ports_user)
    if scan_mode == "fast":
        return list(TOP_100_PORTS)
    if scan_mode == "top_1000":
        return get_top_1000_ports()
    if scan_mode == "full":
        return list(range(1, 65536))
    # Unknown/legacy mode: treat as user port range
    return parse_port_range_fn(port_range or "1-1000", max_ports=max_ports_user)


def _err_result(
    target: str,
    scan_type: str,
    scan_mode: str,
    error: str,
) -> dict:
    return {
        "target": target,
        "scan_type": scan_type,
        "scan_mode": scan_mode,
        "hosts": [],
        "open_ports": [],
        "hosts_scanned": [],
        "total_ports_checked": 0,
        "error": error,
    }


def _udp_probe(host: str, port: int, timeout: float) -> dict | None:
    """UDP probe: send datagram; timeout → open|filtered. No root required."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 4, (host, port))
            try:
                s.recvfrom(1024)
                pass
            except socket.timeout:
                pass
            return {
                "port": port,
                "protocol": "udp",
                "service": SERVICE_NAMES.get(port, "unknown"),
                "banner": "",
                "state": "open|filtered",
                "version": "",
            }
    except OSError:
        return None


def _run_udp_scan(
    hosts: list[str],
    ports: list[int],
    timeout: float,
    progress_cb: Optional[Callable[[int], None]],
) -> dict[str, list[dict]]:
    """Run UDP probe on each host; return result_by_host."""
    result_by_host: dict[str, list[dict]] = {h: [] for h in hosts}
    total = len(hosts) * len(ports)
    completed = [0]
    for host in hosts:
        with ThreadPoolExecutor(max_workers=50) as exe:
            futures = {exe.submit(_udp_probe, host, p, timeout): (host, p) for p in ports}
            for future in as_completed(futures):
                host, _ = futures[future]
                completed[0] += 1
                if progress_cb and total > 0:
                    progress_cb(int((completed[0] / total) * 100))
                try:
                    r = future.result()
                    if r:
                        result_by_host[host].append(r)
                except Exception:
                    pass
    return result_by_host


def _run_ping_scan(
    hosts: list[str],
    timeout: float,
    progress_cb: Optional[Callable[[int], None]],
) -> tuple[list[str], int]:
    """
    Ping sweep = host discovery only. Probes each host via TCP (80/443/22).
    Returns (hosts_up, hosts_down_count).
    """
    live = host_discovery.probe_hosts_for_ping_sweep(
        hosts, timeout=timeout, progress_cb=progress_cb
    )
    if progress_cb:
        progress_cb(100)
    return live, len(hosts) - len(live)


def run_scan(
    target: str,
    port_range: str,
    scan_type: str = "tcp-connect",
    scan_mode: str = "normal",
    skip_discovery: bool = False,
    timing_profile: Optional[str] = None,
    timeout: Optional[float] = None,
    max_workers: int = 50,
    progress_cb: Optional[Callable[[int], None]] = None,
    parse_port_range_fn=None,
    max_ports_user: int = 1000,
) -> dict:
    """
    Run a scan. Uses socket-based connect scan by default; SYN when available and requested.

    Returns dict with: target, scan_type, scan_mode, hosts[], open_ports[], hosts_scanned,
    total_ports_checked, error. Each port in hosts[].ports and open_ports has:
    port, protocol, state, service, version, banner.
    """
    from backend.utils.validators import parse_port_range, validate_target

    if parse_port_range_fn is None:
        parse_port_range_fn = parse_port_range

    ok, err = validate_target(target)
    if not ok:
        return _err_result(target, scan_type, scan_mode, err)

    hosts = resolve_target(target)
    if not hosts:
        return _err_result(target, scan_type, scan_mode, f"Could not resolve target: {target!r}")

    mode_cfg = SCAN_MODE_CONFIG.get(scan_mode, SCAN_MODE_CONFIG["normal"])
    effective_timeout = timeout if timeout is not None else mode_cfg.get("timeout", 2.0)

    # ── Ping sweep: host discovery only, no port scanning ───────────────────
    if scan_type == "ping":
        logger.info("Ping sweep start: target=%r hosts_to_probe=%d", target, len(hosts))
        hosts_up, hosts_down_count = _run_ping_scan(hosts, effective_timeout, progress_cb)
        logger.info(
            "Ping sweep complete: target=%r hosts_up=%d hosts_down=%d",
            target, len(hosts_up), hosts_down_count,
        )
        return {
            "target": target,
            "scan_type": "ping",
            "scan_mode": scan_mode,
            "hosts_up": hosts_up,
            "hosts_down_count": hosts_down_count,
            "total_hosts_scanned": len(hosts),
            "open_ports": [],  # Backward compat
            "hosts": [{"ip": ip, "ports": []} for ip in hosts_up],
            "hosts_scanned": hosts_up,
            "total_ports_checked": 0,
            "error": None,
        }

    # ── Port scans: resolve ports and run ───────────────────────────────────
    try:
        ports = _get_ports_for_mode(scan_mode, port_range, parse_port_range_fn, max_ports_user)
    except ValueError as e:
        return _err_result(target, scan_type, scan_mode, str(e))

    if not ports:
        return _err_result(target, scan_type, scan_mode, "No ports to scan")

    logger.info(
        "Scan start: target=%r scan_type=%s scan_mode=%s port_count=%d (mode=%s)",
        target, scan_type, scan_mode, len(ports),
        "user_ports" if scan_mode in USER_PORT_MODES else "predefined",
    )
    if scan_mode in USER_PORT_MODES and len(ports) <= 20:
        logger.debug("Port list: %s", ports)
    elif scan_mode in USER_PORT_MODES:
        logger.debug("Port range: %s..%s (%d ports)", min(ports), max(ports), len(ports))

    effective_timing = timing_profile or mode_cfg.get("timing", "T3")
    randomize = mode_cfg.get("randomize_ports", False)
    run_service_detection = mode_cfg.get("service_detection", True)
    grab_banner = run_service_detection and scan_type != "udp"

    if randomize:
        ports = timing_engine.randomize_port_order(ports)

    # Host discovery (skip for -Pn)
    if scan_type != "udp":
        hosts = host_discovery.filter_live_hosts(hosts, skip_discovery=skip_discovery)
    if not hosts:
        return _err_result(target, scan_type, scan_mode, "No hosts to scan after discovery")

    result_by_host: dict[str, list[dict]] = {}
    if scan_type == "udp":
        result_by_host = _run_udp_scan(hosts, ports, effective_timeout, progress_cb)
        hosts_list, open_ports_flat = build_hosts_and_open_ports(
            result_by_host, False, effective_timeout
        )
    elif scan_type == "tcp-syn" and is_syn_scan_available():
        syn_result = run_syn_scan(
            hosts, ports, timeout=effective_timeout,
            timing_profile=effective_timing, max_workers=max_workers, progress_cb=progress_cb,
        )
        if syn_result is None:
            result_by_host = connect_scan.run_connect_scan(
                hosts, ports, timeout=effective_timeout, timing_profile=effective_timing,
                max_workers=max_workers, grab_banner=grab_banner, progress_cb=progress_cb,
            )
        else:
            result_by_host = syn_result
        hosts_list, open_ports_flat = build_hosts_and_open_ports(
            result_by_host, run_service_detection, effective_timeout
        )
    else:
        result_by_host = connect_scan.run_connect_scan(
            hosts, ports, timeout=effective_timeout, timing_profile=effective_timing,
            max_workers=max_workers, grab_banner=grab_banner, progress_cb=progress_cb,
        )
        hosts_list, open_ports_flat = build_hosts_and_open_ports(
            result_by_host, run_service_detection, effective_timeout
        )

    total_ports_checked = len(hosts) * len(ports) if scan_type != "ping" else 0
    logger.info(
        "Scan complete: target=%r scan_mode=%s hosts=%d ports_checked=%d open=%d",
        target, scan_mode, len(hosts), total_ports_checked, len(open_ports_flat),
    )
    return {
        "target": target,
        "scan_type": scan_type,
        "scan_mode": scan_mode,
        "hosts": hosts_list,
        "open_ports": open_ports_flat,
        "hosts_scanned": hosts,
        "total_ports_checked": total_ports_checked,
        "error": None,
    }


__all__ = ["run_scan", "resolve_target", "is_syn_scan_available"]
