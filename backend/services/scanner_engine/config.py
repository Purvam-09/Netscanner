"""
backend/services/scanner_engine/config.py
-----------------------------------------
Port lists and timing configuration for Nmap-style scan modes.

Nmap mapping:
  - fast / top 100  →  nmap -F / --top-ports 100
  - top_1000        →  --top-ports 1000
  - full            →  -p-  (all ports 1-65535)
  - stealth_connect →  -sT -T2  (connect scan, polite timing)
  - normal          →  -sT  (default connect)
"""

# Top 100 most commonly open ports (frequency-based, Nmap -F style).
# Source: common practice / Nmap port frequency data.
TOP_100_PORTS: list[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

# Top 1000: use range 1-1000 as a simple default (Nmap's actual list is frequency-based).
# For a closer match, extend with more high ports; here we use 1-1000 for predictability.
def get_top_1000_ports() -> list[int]:
    """Return list of top 1000 ports. Nmap equivalent: --top-ports 1000."""
    return list(range(1, 1001))


def get_full_port_list() -> list[int]:
    """All TCP ports 1-65535. Nmap equivalent: -p-."""
    return list(range(1, 65536))


# Timing profiles (Nmap -T0..-T5). We implement T2 (polite), T3 (normal), T4 (aggressive).
# T2: longer delays, randomized; T3: default; T4: minimal delay.
TIMING_PROFILES = {
    "T2": {"min_delay_ms": 100, "max_delay_ms": 500, "timeout": 3.0, "retries": 1},
    "T3": {"min_delay_ms": 10, "max_delay_ms": 100, "timeout": 2.0, "retries": 1},
    "T4": {"min_delay_ms": 0, "max_delay_ms": 10, "timeout": 1.5, "retries": 0},
}

DEFAULT_TIMING = "T3"
DEFAULT_CONNECT_TIMEOUT = 2.0

# Scan mode defaults (timeout and whether to randomize / use delays).
# Allowed scan modes (single source of truth)
ALLOWED_SCAN_MODES = ("fast", "top_1000", "full", "stealth_connect", "normal")
USER_PORT_MODES = ("normal", "stealth_connect")  # Modes that use user-entered ports only
PREDEFINED_PORT_MODES = ("fast", "top_1000", "full")  # Modes that ignore user port input

SCAN_MODE_CONFIG = {
    "fast": {
        "port_list": TOP_100_PORTS,
        "timeout": 2.0,
        "timing": "T3",
        "randomize_ports": True,
        "service_detection": True,
    },
    "top_1000": {
        "port_list_factory": get_top_1000_ports,
        "timeout": 2.0,
        "timing": "T3",
        "randomize_ports": True,
        "service_detection": True,
    },
    "full": {
        "port_list_factory": get_full_port_list,
        "timeout": 1.5,
        "timing": "T4",
        "randomize_ports": True,
        "service_detection": False,  # too slow for 65k ports by default
    },
    "stealth_connect": {
        "port_list": None,  # use user port_range
        "timeout": 1.0,
        "timing": "T2",
        "randomize_ports": True,
        "service_detection": False,  # no banner to reduce noise
    },
    "normal": {
        "port_list": None,  # use user port_range
        "timeout": 2.0,
        "timing": "T3",
        "randomize_ports": False,
        "service_detection": True,
    },
}
