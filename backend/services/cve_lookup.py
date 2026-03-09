"""
backend/services/cve_lookup.py
--------------------------------
Vulnerability lookup service using the NVD (National Vulnerability Database) API.

For each open port service (e.g. "http", "ssh"), we search NVD for recent CVEs.
Results are cached in the cve_cache table (TTL = 1 hour by default).

Usage:
    results = lookup_cves_for_ports(open_ports, db_path, ttl=3600)
    # open_ports: list of {"port": 80, "service": "http", ...}
    # Returns: dict keyed by service name, value is list of CVE dicts
"""
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

from backend.models.db import get_db

logger = logging.getLogger(__name__)

NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 8   # seconds
MAX_RESULTS     = 5   # CVEs per service to keep things concise

# ── Public API ────────────────────────────────────────────────────────────────

def lookup_cves_for_ports(
    open_ports: list[dict],
    db_path: str | Path,
    ttl: int = 3600,
) -> dict[str, list[dict]]:
    """
    Given a list of open port dicts, return a mapping:
        { "service_name": [cve_dict, ...], ... }

    Each cve_dict:
        { "id", "description", "severity", "cvss_score", "published", "url" }
    """
    services = {
        p["service"]
        for p in open_ports
        if p.get("service") and p["service"] not in ("unknown", "")
    }

    results: dict[str, list[dict]] = {}
    for service in services:
        cves = _get_cached_or_fetch(service, db_path, ttl)
        if cves is not None:
            results[service] = cves

    return results


# ── Cache helpers ─────────────────────────────────────────────────────────────

def _get_cached_or_fetch(
    service: str, db_path: str | Path, ttl: int
) -> Optional[list[dict]]:
    """Return cached CVEs if fresh, otherwise fetch from NVD and cache."""
    with get_db(db_path) as conn:
        row = conn.execute(
            "SELECT cves_json, fetched_at FROM cve_cache WHERE service = ?", (service,)
        ).fetchone()

    if row:
        try:
            fetched_at = datetime.fromisoformat(row["fetched_at"])
            age = (datetime.utcnow() - fetched_at).total_seconds()
            if age < ttl:
                return json.loads(row["cves_json"])
        except Exception:
            pass

    # Fetch from NVD
    cves = _fetch_nvd(service)
    if cves is not None:
        _cache(service, cves, db_path)

    return cves


def _fetch_nvd(service: str) -> Optional[list[dict]]:
    """Fetch CVEs from NVD API for a service keyword."""
    try:
        params = {
            "keywordSearch": service,
            "keywordExactMatch": "",
            "resultsPerPage": MAX_RESULTS,
            "startIndex": 0,
        }
        resp = requests.get(NVD_API_BASE, params=params, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in desc_list if d.get("lang") == "en"), ""
                )
                # CVSS score
                metrics = cve.get("metrics", {})
                score, severity = _extract_score(metrics)

                cves.append({
                    "id":          cve_id,
                    "description": desc[:300],
                    "severity":    severity,
                    "cvss_score":  score,
                    "published":   cve.get("published", "")[:10],
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
            logger.info("NVD: fetched %d CVEs for service=%r", len(cves), service)
            return cves
        else:
            logger.warning("NVD API returned %s for service=%r", resp.status_code, service)
            return None
    except requests.RequestException as e:
        logger.warning("NVD API request failed for service=%r: %s", service, e)
        return None


def _extract_score(metrics: dict) -> tuple[float | None, str]:
    """Extract CVSS base score and severity from metrics dict."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data   = entries[0].get("cvssData", {})
            score  = data.get("baseScore")
            sev    = data.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN"))
            return score, sev
    return None, "UNKNOWN"


def _cache(service: str, cves: list[dict], db_path: str | Path) -> None:
    """Upsert cached CVEs for a service."""
    try:
        with get_db(db_path) as conn:
            conn.execute(
                """INSERT INTO cve_cache (service, cves_json, fetched_at)
                   VALUES (?, ?, datetime('now'))
                   ON CONFLICT(service) DO UPDATE
                   SET cves_json=excluded.cves_json, fetched_at=excluded.fetched_at""",
                (service, json.dumps(cves)),
            )
            conn.commit()
    except Exception as e:
        logger.warning("Failed to cache CVEs for %r: %s", service, e)