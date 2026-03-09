"""
backend/services/discovery_ping.py
-----------------------------------
Host discovery via ICMP ping — Angry IP Scanner style.
Generates IP list from range or CIDR, pings each host in parallel, returns status + latency.

Optimized for /24 networks (~254 hosts) to complete in 1–3 seconds:
  - Short ping timeout (300ms Windows / 1s Linux)
  - High concurrency (200 threads) for parallel subprocess execution
  - Deferred hostname resolution (batched after ping phase)
"""
import ipaddress
import logging
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Angry IP–style: short timeout for fast sweep (dead hosts don't block)
PING_TIMEOUT_MS = 300   # Windows: -w 300ms
PING_TIMEOUT_SEC = 1    # Linux/macOS: -W 1 (min practical)
PING_COUNT = 1
MAX_WORKERS = 200       # High concurrency for /24 (~254 hosts) in 1–2 waves
# Max hosts to prevent runaway scans (e.g. /16 = 65536 hosts)
MAX_HOSTS = 1024


def _generate_ips_from_range(start_ip: str, end_ip: str) -> list[str]:
    """Generate list of IPv4 addresses from start to end inclusive."""
    try:
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        if start.version != 4 or end.version != 4:
            return []
        if start > end:
            start, end = end, start
        ips = []
        current = start
        while current <= end and len(ips) < MAX_HOSTS:
            ips.append(str(current))
            current += 1
        return ips
    except ValueError:
        return []


def _generate_ips_from_cidr(cidr: str) -> list[str]:
    """Generate list of IPv4 addresses from CIDR (e.g. 192.168.1.0/24)."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        if net.version != 4:
            return []
        hosts = list(net.hosts())
        return [str(h) for h in hosts[:MAX_HOSTS]]
    except ValueError:
        return []


def _resolve_hostname(ip: str) -> str | None:
    """Reverse DNS lookup with short timeout. Returns hostname or None."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def _ping_host(ip: str) -> dict:
    """
    Ping a single host. Returns dict with ip, status, latency (ms), hostname.
    Hostname resolution is deferred to avoid blocking; caller runs it in batch.
    """
    result = {"ip": ip, "status": "dead", "latency": None, "hostname": None}

    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT_MS), ip]
            proc_timeout = (PING_TIMEOUT_MS / 1000) + 0.5
        else:
            cmd = ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT_SEC), ip]
            proc_timeout = PING_TIMEOUT_SEC + 1

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=proc_timeout,
        )

        output = (proc.stdout or "") + (proc.stderr or "")

        latency_match = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", output, re.I)
        if latency_match:
            result["latency"] = f"{float(latency_match.group(1)):.0f}ms"

        if proc.returncode == 0 or "ttl=" in output.lower() or "reply from" in output.lower():
            result["status"] = "alive"
        else:
            result["status"] = "dead"
            if not result["latency"]:
                result["latency"] = "Timeout"

    except subprocess.TimeoutExpired:
        result["status"] = "dead"
        result["latency"] = "Timeout"
    except Exception as e:
        logger.debug("Ping error for %s: %s", ip, e)
        result["status"] = "dead"
        result["latency"] = "Error"

    return result


def _resolve_hostnames_for_alive(results: list[dict]) -> None:
    """Resolve hostnames for alive hosts in parallel (mutates results in place)."""
    alive = [r for r in results if r["status"] == "alive"]
    if not alive:
        return

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(0.5)
    try:
        def do_resolve(r: dict) -> None:
            hn = _resolve_hostname(r["ip"])
            if hn:
                r["hostname"] = hn

        with ThreadPoolExecutor(max_workers=min(50, len(alive))) as exe:
            list(exe.map(do_resolve, alive))
    finally:
        socket.setdefaulttimeout(old_timeout)


def run_discovery(
    start_ip: str | None = None,
    end_ip: str | None = None,
    cidr: str | None = None,
) -> list[dict]:
    """
    Run host discovery scan.
    Provide either (start_ip + end_ip) OR cidr.
    Returns list of dicts: { ip, status, latency, hostname }
    """
    ips: list[str] = []

    if cidr:
        ips = _generate_ips_from_cidr(cidr)
    elif start_ip and end_ip:
        ips = _generate_ips_from_range(start_ip, end_ip)
    else:
        return []

    if not ips:
        return []

    results: list[dict] = []
    total = len(ips)

    workers = min(MAX_WORKERS, total)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_ping_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            try:
                r = future.result()
                results.append(r)
            except Exception as e:
                ip = futures.get(future, "?")
                logger.debug("Discovery error for %s: %s", ip, e)
                results.append({
                    "ip": str(ip),
                    "status": "dead",
                    "latency": "Error",
                    "hostname": None,
                })

    # Deferred hostname resolution (parallel, doesn't block ping phase)
    _resolve_hostnames_for_alive(results)

    results.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return results
