"""
backend/services/scanner_engine/port_parser.py
-----------------------------------------------
Single source of truth for parsing user port input.

Accepts: '1-1000', '80,443,8080', single port, comma/range combinations.
Returns sorted, deduplicated list, capped at max_ports.
"""
import re

_PORT_ATOM_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")

DEFAULT_MAX_PORTS = 1000


def parse_port_range(port_range: str, max_ports: int = DEFAULT_MAX_PORTS) -> list[int]:
    """
    Parse port string (e.g. '1-1000', '80,443', '22').
    Returns sorted, deduplicated list capped at max_ports.
    Raises ValueError on invalid input.
    """
    raw = (port_range or "1-1000").strip().replace(" ", "")
    ports: set[int] = set()

    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if not _PORT_ATOM_RE.match(part):
            raise ValueError(f"Invalid port spec: {part!r}")
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
                raise ValueError(f"Port range out of bounds: {part!r}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)

    result = sorted(ports)
    return result[:max_ports]
