"""
backend/services/scanner_engine/results.py
------------------------------------------
Normalize scan output format. Single source of truth for result structure.

Every port entry has: port, protocol, state, service, version, banner.
Used by: engine, export_service, cve_lookup, API responses, UI.
"""
from backend.services.scanner_engine import service_detection
from backend.services.scanner_engine.service_detection import DEFAULT_SERVICE_BY_PORT

# Re-export for backward compatibility
SERVICE_NAMES = DEFAULT_SERVICE_BY_PORT


def normalize_port_entry(
    p: dict,
    port_num: int,
    run_service_detection: bool,
    ip: str,
    timeout: float,
) -> dict:
    """
    Ensure port dict has consistent format: port, protocol, state, service, version, banner.
    """
    service = p.get("service") or SERVICE_NAMES.get(port_num, "unknown")
    version = p.get("version", "")
    banner = p.get("banner", "")

    if run_service_detection and port_num is not None:
        if banner:
            svc, ver = service_detection.parse_banner(banner, port_num)
        else:
            svc, ver = service_detection.probe_service(
                ip, port_num, timeout=min(timeout, 2.0)
            )
        if svc:
            service = svc
        if ver:
            version = ver

    return {
        "port": port_num,
        "protocol": p.get("protocol", "tcp"),
        "state": p.get("state", "open"),
        "service": service,
        "version": version or "",
        "banner": banner,
    }


def build_hosts_and_open_ports(
    result_by_host: dict[str, list[dict]],
    run_service_detection: bool,
    timeout: float,
) -> tuple[list[dict], list[dict]]:
    """
    Convert result_by_host to hosts[] and flat open_ports[].
    Each port entry is normalized to standard format.
    """
    hosts_list = []
    open_ports_flat = []

    for ip, ports in result_by_host.items():
        enriched = []
        for p in ports:
            port_num = p.get("port")
            entry = normalize_port_entry(
                p, port_num, run_service_detection, ip, timeout
            )
            enriched.append(entry)
            open_ports_flat.append(entry)
        hosts_list.append({"ip": ip, "ports": enriched})

    return hosts_list, open_ports_flat
