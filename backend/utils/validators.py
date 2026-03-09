"""
backend/utils/validators.py
-----------------------------
Input validation helpers used by blueprints.
All functions return (ok: bool, error_message: str).
"""
import ipaddress
import re

from backend.services.scanner_engine.port_parser import (
    DEFAULT_MAX_PORTS,
    parse_port_range,
)

# Re-export for backward compatibility
MAX_PORTS = DEFAULT_MAX_PORTS
__all__ = [
    "validate_target",
    "parse_port_range",
    "validate_email",
    "validate_username",
    "validate_cron",
    "validate_target_type",
    "is_private_ip",
    "is_private_network",
]

# ── Patterns ──────────────────────────────────────────────────────────────────
# Hostname: letters, digits, hyphens, dots. No leading/trailing hyphen per label.
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_HOSTNAME_LEN = 253


def _validate_single_target(t: str) -> tuple[bool, str]:
    """Validate one target (IP, CIDR, or hostname). Returns (ok, error)."""
    if not t or len(t) > MAX_HOSTNAME_LEN:
        return False, "Target is required" if not t else f"Target too long (max {MAX_HOSTNAME_LEN} chars)"

    # Block obvious injection attempts
    if any(c in t for c in (";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r")):
        return False, "Target contains invalid characters"

    # CIDR
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.version != 4:
                return False, "Only IPv4 targets are supported"
            return True, ""
        except ValueError:
            return False, "Invalid CIDR notation"

    # Plain IPv4
    if re.match(r"^[\d.]+$", t):
        try:
            addr = ipaddress.ip_address(t)
            if addr.version != 4:
                return False, "Only IPv4 addresses are supported"
            return True, ""
        except ValueError:
            return False, "Invalid IP address"

    # Hostname
    if _HOSTNAME_RE.match(t):
        return True, ""

    return False, "Target must be a valid IPv4 address, CIDR, or hostname"


def validate_target(target: str) -> tuple[bool, str]:
    """
    Accept: IPv4, IPv4 CIDR, hostname, or comma/newline-separated list of these.
    Reject: IPv6 (not supported by scanner engine yet), shell metacharacters.
    """
    if not target:
        return False, "Target is required"
    t = target.strip()
    if len(t) > 8192:
        return False, "Target input too long"

    # Block obvious injection attempts
    if any(c in t for c in (";", "&", "|", "`", "$", "(", ")", "<", ">")):
        return False, "Target contains invalid characters"

    # Split by comma and newline for multi-target support
    parts = re.split(r"[\s,]+", t)
    parts = [p.strip() for p in parts if p.strip()]

    if not parts:
        return False, "Target is required"

    for part in parts:
        ok, err = _validate_single_target(part)
        if not ok:
            return False, f"{part!r}: {err}"

    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    if not email or not _EMAIL_RE.match(email.strip()):
        return False, "Invalid email address"
    if len(email) > 254:
        return False, "Email too long"
    return True, ""


def validate_username(username: str) -> tuple[bool, str]:
    u = (username or "").strip()
    if not u:
        return False, "Username is required"
    if len(u) < 3:
        return False, "Username must be at least 3 characters"
    if len(u) > 64:
        return False, "Username too long (max 64)"
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", u):
        return False, "Username may only contain letters, digits, _, -, ."
    return True, ""


def validate_cron(expr: str) -> tuple[bool, str]:
    """Basic 5-field cron validation (minute hour dom month dow)."""
    parts = (expr or "").strip().split()
    if len(parts) != 5:
        return False, "Cron expression must have 5 fields (e.g. '0 */6 * * *')"
    return True, ""


def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address is private (RFC 1918).
    Returns True for: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x (localhost)
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def is_private_network(cidr_str: str) -> bool:
    """
    Check if a CIDR network is private.
    Returns True if all hosts in the network are private IPs.
    """
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
        # Check if network is in private ranges
        return net.is_private or any(
            net.overlaps(ipaddress.ip_network(prefix))
            for prefix in ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        )
    except ValueError:
        return False


def validate_target_type(target: str, target_type: str) -> tuple[bool, str]:
    """
    Validate that target(s) match the selected target_type.
    Supports comma/newline-separated multi-target.
    
    Args:
        target: IP address, CIDR, hostname, or comma/newline-separated list
        target_type: "public" or "private"
    
    Returns:
        (ok: bool, error_message: str)
    """
    if not target_type or target_type not in ("public", "private"):
        return True, ""  # If target_type not provided, skip validation

    parts = re.split(r"[\s,]+", target)
    parts = [p.strip() for p in parts if p.strip()]

    for t in parts:
        ok, err = _validate_target_type_single(t.lower(), target_type)
        if not ok:
            return False, err
    return True, ""


def _validate_target_type_single(t: str, target_type: str) -> tuple[bool, str]:
    """Validate one target against target_type."""
    if not t:
        return True, ""

    # Handle localhost as private
    if t == "localhost":
        if target_type == "public":
            return False, "Public target type cannot use localhost. Use public IPs or hostnames."
        return True, ""

    # CIDR check
    if "/" in t:
        is_private = is_private_network(t)
        if target_type == "private" and not is_private:
            return False, "Private target type requires a private IP range (e.g. 192.168.1.0/24, 10.0.0.0/8)"
        if target_type == "public" and is_private:
            return False, "Public target type cannot use private IP ranges. Use public IPs or hostnames."
        return True, ""

    # Plain IP check
    if re.match(r"^[\d.]+$", t):
        try:
            addr = ipaddress.ip_address(t)
            is_private = addr.is_private or addr.is_loopback

            if target_type == "private" and not is_private:
                return False, "Private target type requires a private IP (e.g. 192.168.1.1, 10.0.0.1, localhost)"
            if target_type == "public" and is_private:
                return False, "Public target type cannot use private IPs. Use public IPs or hostnames."
            return True, ""
        except ValueError:
            pass

    # Hostname check
    if _HOSTNAME_RE.match(t):
        # Hostnames are always considered public (require DNS/internet)
        if target_type == "private":
            return False, "Private target type requires an IP address or CIDR range, not a hostname."
        return True, ""

    return True, ""  # If we can't determine, let other validation handle it