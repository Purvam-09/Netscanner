"""
backend/services/scanner_engine/timing_engine.py
-------------------------------------------------
Timing and evasion: randomized port order, delays between probes.

Nmap mapping:
  - T2  →  Polite (slower, less likely to trigger IDS)
  - T3  →  Normal (default)
  - T4  →  Aggressive (faster, no delay)
"""
import random
import time
from typing import Callable, Optional

from backend.services.scanner_engine.config import (
    DEFAULT_TIMING,
    TIMING_PROFILES,
)


def get_timing_config(profile: str) -> dict:
    """Return delay bounds and timeout for a timing profile (T2, T3, T4)."""
    return TIMING_PROFILES.get(profile, TIMING_PROFILES[DEFAULT_TIMING]).copy()


def randomize_port_order(ports: list[int], seed: Optional[int] = None) -> list[int]:
    """Return a shuffled copy of ports to reduce scan predictability. Nmap-style evasion."""
    out = list(ports)
    if seed is not None:
        rng = random.Random(seed)
        rng.shuffle(out)
    else:
        random.shuffle(out)
    return out


def delay_between_probes(profile: str) -> None:
    """
    Sleep a random amount within the profile's delay range.
    Call between probes to mimic Nmap timing (e.g. T2 = polite).
    """
    cfg = get_timing_config(profile)
    min_ms = cfg.get("min_delay_ms", 0)
    max_ms = cfg.get("max_delay_ms", 0)
    if max_ms <= 0:
        return
    delay_sec = random.uniform(min_ms / 1000.0, max_ms / 1000.0)
    if delay_sec > 0:
        time.sleep(delay_sec)


def should_delay_between_probes(profile: str) -> bool:
    """True if this profile uses inter-probe delays."""
    cfg = get_timing_config(profile)
    return (cfg.get("max_delay_ms") or 0) > 0
