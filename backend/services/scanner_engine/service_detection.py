"""
backend/services/scanner_engine/service_detection.py
-----------------------------------------------------
Service and version detection from banners (-sV style).

After TCP connect we send protocol-specific probes (or read initial banner),
then match against known patterns to identify service name and version.
Does NOT call Nmap; uses banner parsing and regex only.
"""
import re
import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Default timeout for banner read / probe.
BANNER_TIMEOUT = 2.0

# ── Banner / version regex patterns (service name, optional version) ───────────
# Format: (service_key, pattern). Capturing group 1 = version if present.
VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh", re.compile(r"^SSH-(\d+\.\d+[^\s-]*(?:-\S+)?)", re.I)),
    ("ssh", re.compile(r"OpenSSH[_\-]?(\d+[^\s]*)", re.I)),
    ("ftp", re.compile(r"^220[^\d]*(\d+[^\r\n]*)", re.I)),
    ("ftp", re.compile(r"([A-Za-z0-9_\-]+)\s+ftp\s+server", re.I)),
    ("smtp", re.compile(r"^220\s+[^\s]+\s+([^\r\n]+)", re.I)),
    ("http", re.compile(r"Server:\s*([^\r\n]+)", re.I)),
    ("http", re.compile(r"Apache[/\s](\d+[^\s\r\n]*)", re.I)),
    ("http", re.compile(r"nginx/(\d+[^\s\r\n]*)", re.I)),
    ("http", re.compile(r"Microsoft-IIS/(\d+[^\s\r\n]*)", re.I)),
    ("mysql", re.compile(r"(\d+\.\d+[^\s.-]*)", re.I)),  # MySQL banner starts with version
    ("postgresql", re.compile(r"(\d+\.\d+[^\s]*)", re.I)),
    ("redis", re.compile(r"REDIS(\d+[^\r\n]*)", re.I)),
    ("redis", re.compile(r"redis_version:(\S+)", re.I)),
    ("telnet", re.compile(r"([^\r\n]+)", re.I)),
    ("pop3", re.compile(r"^\+OK[^\r\n]*", re.I)),
    ("imap", re.compile(r"\*\s+OK[^\r\n]*", re.I)),
    ("rdp", re.compile(r"(\d+\.\d+\.\d+)", re.I)),
    ("vnc", re.compile(r"RFB\s+(\d+\.\d+[^\r\n]*)", re.I)),
    ("mongodb", re.compile(r"(\d+\.\d+\.\d+)", re.I)),
]

# Port → default service name when no banner match.
DEFAULT_SERVICE_BY_PORT: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 443: "https", 445: "smb", 587: "smtp-sub",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt2", 27017: "mongodb",
}


def _recv_banner(sock: socket.socket, timeout: float = BANNER_TIMEOUT, max_bytes: int = 1024) -> str:
    """Read initial response from socket; decode as UTF-8, strip."""
    try:
        sock.settimeout(timeout)
        data = sock.recv(max_bytes)
        return data.decode("utf-8", errors="replace").strip()[:500]
    except Exception:
        return ""


def _probe_http(host: str, port: int, timeout: float) -> str:
    """Send GET / and return response start (for Server header)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            return _recv_banner(s, timeout=timeout)
    except Exception:
        return ""


def _probe_ftp(host: str, port: int, timeout: float) -> str:
    """Connect and read 220 banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return _recv_banner(s, timeout=timeout)
    except Exception:
        return ""


def _probe_generic(host: str, port: int, timeout: float) -> str:
    """Connect and read first chunk (SSH, SMTP, etc.)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return _recv_banner(s, timeout=timeout)
    except Exception:
        return ""


def _match_version(banner: str, port: int) -> tuple[str, str]:
    """
    Return (service_name, version_string) from banner.
    version_string may be empty.
    """
    service = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")
    version = ""
    banner_lower = banner.lower()

    for svc, pattern in VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            service = svc
            if m.lastindex and m.lastindex >= 1:
                version = (m.group(1) or "").strip()
            break

    # Normalize http/https
    if port in (443, 8443, 8080, 8888) and service == "http":
        service = "https" if port in (443, 8443) else "http-alt"
    return service, version


def parse_banner(banner: str, port: int) -> tuple[str, str]:
    """
    Extract (service_name, version_string) from an existing banner string.
    Use when we already have banner from connect scan to avoid a second connection.
    """
    if not (banner or banner.strip()):
        return DEFAULT_SERVICE_BY_PORT.get(port, "unknown"), ""
    return _match_version(banner.strip(), port)


def probe_service(
    host: str,
    port: int,
    timeout: float = BANNER_TIMEOUT,
    skip_banner: bool = False,
) -> tuple[str, str]:
    """
    Perform service/version detection for (host, port).
    Returns (service_name, version_string). If skip_banner=True, return (default_service, "").
    """
    if skip_banner:
        service = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")
        return service, ""

    banner = ""
    if port in (80, 8080, 8000, 8888, 8008):
        banner = _probe_http(host, port, timeout)
    elif port == 21:
        banner = _probe_ftp(host, port, timeout)
    else:
        banner = _probe_generic(host, port, timeout)

    if not banner:
        service = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")
        return service, ""
    return _match_version(banner, port)
