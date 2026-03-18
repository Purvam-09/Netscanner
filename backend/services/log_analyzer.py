"""
backend/services/log_analyzer.py
--------------------------------
Streaming, rule-based log analyzer with structured security output.

Goals:
- Parse multiple sources: Nmap output, Apache/Nginx access logs, app logs, JSONL and plain text.
- Extract security insights: risky open ports/services, suspicious IPs, brute-force attempts, repeated requests.
- Structured output: JSON-ready issues with severity + recommendation, plus a dashboard summary.
- Performance: stream line-by-line (no full-file reads), regex-based parsing.
- Modular design: parsers, rule engine, reporting in separate classes.

Backwards-compatibility:
- The existing Flask route imports `analyze_log()` and expects:
  `total_events`, `errors`, `warnings`, `failed_logins`.
  This function still returns those fields, and also includes:
  `issues`, `summary_dashboard`, `meta`.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from itertools import chain
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, Union


# ==========================
# Models
# ==========================


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(frozen=True)
class LogEvent:
    """
    Normalized log event from any supported source.
    """

    source: str
    timestamp: Optional[datetime]
    ip: Optional[str]
    raw: str
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class SecurityIssue:
    """
    Structured finding produced by rule analysis.
    """

    ip: Optional[str]
    issue: str
    severity: Severity
    recommendation: str
    # High-level classification of the attack (Brute Force, SQL Injection, XSS, etc.).
    attack_type: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[datetime] = None
    details: Dict[str, Any] = None
    # Number of times this (ip, issue) combination was observed.
    count: int = 1

    def to_json(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.timestamp is not None:
            data["timestamp"] = self.timestamp.isoformat()
        if data.get("details") is None:
            data["details"] = {}
        data["severity"] = self.severity.value
        # Always include an attack_type field for downstream consumers.
        if not data.get("attack_type"):
            data["attack_type"] = "Unknown"
        return data


# ==========================
# Utilities
# ==========================


_IP_REGEX = re.compile(
    r"\b(?:(?:2[0-4]\d|25[0-5]|1?\d{1,2})(?:\.(?!$)|$)){4}\b"
)


def extract_first_ip(text: str) -> Optional[str]:
    m = _IP_REGEX.search(text)
    return m.group(0) if m else None


def parse_timestamp(text: str) -> Optional[datetime]:
    """
    Try common log timestamp formats.
    Extend this list if your environment uses other formats.
    """

    if not text:
        return None

    candidates = [
        "%d/%b/%Y:%H:%M:%S %z",  # Apache/Nginx: 10/Oct/2000:13:55:36 -0700
        "%Y-%m-%dT%H:%M:%S%z",  # ISO with timezone
        "%Y-%m-%dT%H:%M:%S",  # ISO without timezone
        "%Y-%m-%d %H:%M:%S",  # generic
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


# ==========================
# Parsers
# ==========================


class BaseLogParser:
    source_name: str

    def parse_line(self, line: str) -> Optional[LogEvent]:
        raise NotImplementedError

    def parse_stream(self, lines: Iterable[str]) -> Iterator[LogEvent]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            evt = self.parse_line(line)
            if evt is not None:
                yield evt


class NmapLogParser(BaseLogParser):
    """
    Parses typical interactive Nmap output (not XML).

    Example lines:
      "Nmap scan report for 192.168.1.10"
      "22/tcp open ssh"
    """

    HOST_REGEX = re.compile(r"Nmap scan report for\s+(.+)$", re.IGNORECASE)
    PORT_REGEX = re.compile(
        r"(?P<port>\d+)\/(?P<proto>tcp|udp)\s+(?P<state>open|closed|filtered)\s+(?P<service>[\w\-]+)",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self.source_name = "nmap"
        self._current_host: Optional[str] = None

    def parse_line(self, line: str) -> Optional[LogEvent]:
        m_host = self.HOST_REGEX.search(line)
        if m_host:
            host = m_host.group(1).strip()
            ip = extract_first_ip(host) or host
            self._current_host = ip
            return LogEvent(
                source=self.source_name,
                timestamp=None,
                ip=ip,
                raw=line,
                metadata={"type": "host", "host": host},
            )

        m_port = self.PORT_REGEX.search(line)
        if m_port and self._current_host:
            gd = m_port.groupdict()
            return LogEvent(
                source=self.source_name,
                timestamp=None,
                ip=self._current_host,
                raw=line,
                metadata={
                    "type": "port",
                    "port": int(gd["port"]),
                    "protocol": gd["proto"].lower(),
                    "state": gd["state"].lower(),
                    "service": gd["service"].lower(),
                },
            )

        return None


class WebServerLogParser(BaseLogParser):
    """
    Parses common Apache/Nginx combined access log format.

    Example:
      127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326
    """

    LOG_REGEX = re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]+))?"\s+'
        r"(?P<status>\d{3})\s+(?P<size>\S+)"
    )

    def __init__(self, source_name: str = "web") -> None:
        self.source_name = source_name

    def parse_line(self, line: str) -> Optional[LogEvent]:
        m = self.LOG_REGEX.match(line)
        if not m:
            return None
        gd = m.groupdict()
        ts = parse_timestamp(gd["ts"])
        size = None if gd["size"] == "-" else int(gd["size"])
        return LogEvent(
            source=self.source_name,
            timestamp=ts,
            ip=gd["ip"],
            raw=line,
            metadata={
                "method": gd["method"],
                "path": gd["path"],
                "protocol": (gd.get("proto") or "").strip(),
                "status": int(gd["status"]),
                "bytes": size,
            },
        )


class JSONLinesParser(BaseLogParser):
    """
    Parses one JSON document per line (JSONL).
    """

    def __init__(
        self,
        source_name: str = "json",
        timestamp_field: str = "timestamp",
        ip_field: str = "ip",
    ) -> None:
        self.source_name = source_name
        self.timestamp_field = timestamp_field
        self.ip_field = ip_field

    def parse_line(self, line: str) -> Optional[LogEvent]:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        raw_ts = data.get(self.timestamp_field) if isinstance(data, dict) else None
        ts = parse_timestamp(raw_ts) if isinstance(raw_ts, str) else None
        ip = None
        if isinstance(data, dict):
            ip_val = data.get(self.ip_field)
            ip = ip_val if isinstance(ip_val, str) else None
        ip = ip or extract_first_ip(line)

        meta = data if isinstance(data, dict) else {"value": data}
        return LogEvent(
            source=self.source_name,
            timestamp=ts,
            ip=ip,
            raw=line,
            metadata=meta,
        )


class PlainTextParser(BaseLogParser):
    """
    Fallback parser for unstructured plaintext logs.
    """

    def __init__(self, source_name: str = "plain") -> None:
        self.source_name = source_name

    def parse_line(self, line: str) -> Optional[LogEvent]:
        return LogEvent(
            source=self.source_name,
            timestamp=None,
            ip=extract_first_ip(line),
            raw=line,
            metadata={"message": line},
        )


class ParserFactory:
    """
    Detects a likely parser by scoring a small sample.
    """

    def __init__(self) -> None:
        self._candidates: List[Tuple[str, BaseLogParser]] = [
            ("nmap", NmapLogParser()),
            ("web", WebServerLogParser("web")),
            ("json", JSONLinesParser("json")),
            ("plain", PlainTextParser("plain")),
        ]

    def detect(self, sample_lines: List[str], file_suffix: str = "") -> BaseLogParser:
        suffix = (file_suffix or "").lower()
        if suffix == ".json":
            # Commonly JSONL in this project; still score to avoid false positives.
            preferred = "json"
        else:
            preferred = ""

        best_score = -1
        best = self._candidates[-1][1]

        for name, parser in self._candidates:
            score = 0
            for line in sample_lines:
                if not line.strip():
                    continue
                if parser.parse_line(line.rstrip("\n")) is not None:
                    score += 1
            if preferred and name == preferred:
                score += 1
            if score > best_score:
                best_score = score
                best = parser

        return best


# ==========================
# Rule engine
# ==========================


class Rule:
    def __init__(
        self,
        name: str,
        func: Callable[[LogEvent, Dict[str, Any]], List[SecurityIssue]],
    ) -> None:
        self.name = name
        self.func = func

    def apply(self, event: LogEvent, context: Dict[str, Any]) -> List[SecurityIssue]:
        return self.func(event, context)


class RuleEngine:
    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self.rules: List[Rule] = rules or []

    def analyze(self, events: Iterable[LogEvent]) -> Iterator[SecurityIssue]:
        context: Dict[str, Any] = {
            "failed_logins": {},  # ip -> count
            "requests": {},  # (ip, path) -> count
            "open_ports": {},  # ip -> set(ports)
        }
        for event in events:
            for rule in self.rules:
                for issue in rule.apply(event, context):
                    yield issue


_FAILED_LOGIN_PATTERNS = [
    re.compile(r"failed\s+login", re.IGNORECASE),
    re.compile(r"login\s+failed", re.IGNORECASE),
    re.compile(r"failed\s+password", re.IGNORECASE),
    re.compile(r"authentication\s+failed", re.IGNORECASE),
    re.compile(r"authentication\s+failure", re.IGNORECASE),
    re.compile(r"invalid\s+password", re.IGNORECASE),
    re.compile(r"unauthorized\s+access", re.IGNORECASE),
    re.compile(r"invalid\s+user", re.IGNORECASE),
]

_SQLI_PATTERNS = [
    re.compile(r"'?\s+or\s+1=1", re.IGNORECASE),
    re.compile(r"\"?\s+or\s+\"1\"=\"1", re.IGNORECASE),
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"or\s+1=1--", re.IGNORECASE),
    re.compile(r"--\s*$"),
    re.compile(r"\bsleep\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"\bbenchmark\(", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
]

_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\\\"),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"/windows/system32", re.IGNORECASE),
]


def default_rules() -> List[Rule]:
    rules: List[Rule] = []

    def smart_nmap_services(event: LogEvent, ctx: Dict[str, Any]) -> List[SecurityIssue]:
        """
        Smarter Nmap analysis that considers service, port and state.
        Only flags open services that are insecure or commonly exploited.
        """
        if event.source != "nmap":
            return []
        if event.metadata.get("type") != "port":
            return []
        if event.metadata.get("state") != "open":
            return []

        ip = event.ip
        port = event.metadata.get("port")
        service = (event.metadata.get("service") or "").lower()

        if ip and isinstance(port, int):
            ctx["open_ports"].setdefault(ip, set()).add(port)

        # Map service/port to risk profile
        # (service_name, port) -> (Severity, reason)
        risk_map: Dict[str, Tuple[Severity, str]] = {
            "telnet": (
                Severity.CRITICAL,
                "Telnet service exposed (unencrypted remote access, clear-text credentials).",
            ),
            "ftp": (
                Severity.MEDIUM,
                "FTP service exposed (clear-text credentials; anonymous/weak auth is common).",
            ),
            "ssh": (
                Severity.LOW,
                "SSH service exposed (ensure strong keys and hardening; watch for brute-force attempts).",
            ),
            "http": (
                Severity.LOW,
                "HTTP service exposed (unencrypted web traffic; avoid sensitive data without TLS).",
            ),
            "https": (
                Severity.LOW,
                "HTTPS service exposed (generally safe; ensure modern TLS config and patching).",
            ),
            "mysql": (
                Severity.MEDIUM,
                "MySQL database exposed (risk of data exfiltration if reachable from untrusted networks).",
            ),
            "mariadb": (
                Severity.MEDIUM,
                "MariaDB database exposed (treat as internet‑facing DB; enforce strict network ACLs).",
            ),
            "microsoft-ds": (
                Severity.HIGH,
                "SMB (445) exposed (lateral movement and ransomware risk; historically exploited heavily).",
            ),
            "smb": (
                Severity.HIGH,
                "SMB service exposed (file sharing over the network; common lateral movement vector).",
            ),
            "ms-wbt-server": (
                Severity.HIGH,
                "RDP (3389) exposed (remote desktop access; frequent brute-force and exploit target).",
            ),
        }

        # If service is unknown or clearly safe, do not emit issues here.
        if not service or service not in risk_map:
            return []

        sev, reason = risk_map[service]

        # Additional port-based refinement without relying solely on port numbers.
        # E.g. Telnet on non-standard port, SMB/RDP on alternate ports.
        if service == "telnet":
            sev = Severity.CRITICAL
        elif service in ("microsoft-ds", "smb"):
            sev = Severity.HIGH
        elif service == "ms-wbt-server":
            sev = Severity.HIGH

        issue_text = f"{service.upper()} service exposed on port {port}"

        return [
            SecurityIssue(
                ip=ip,
                issue=issue_text,
                severity=sev,
                recommendation=(
                    reason
                    + " Restrict exposure to trusted networks only (VPN/firewall), enforce strong authentication, "
                    "and disable the service if not strictly required."
                ),
                attack_type="Service Exposure",
                source=event.source,
                timestamp=event.timestamp,
                details={"port": port, "service": service},
            )
        ]

    rules.append(Rule("smart_nmap_services", smart_nmap_services))

    def brute_force_and_repeats(event: LogEvent, ctx: Dict[str, Any]) -> List[SecurityIssue]:
        ip = event.ip
        if not ip:
            return []

        raw_lower = event.raw.lower()
        issues: List[SecurityIssue] = []

        # Brute-force / failed auth attempts
        if any(p.search(raw_lower) for p in _FAILED_LOGIN_PATTERNS):
            c = ctx["failed_logins"].get(ip, 0) + 1
            ctx["failed_logins"][ip] = c

            # Brute-force: once over threshold, treat as at least High severity.
            if c >= 5:
                if c >= 40:
                    sev = Severity.CRITICAL
                else:
                    sev = Severity.HIGH
                issues.append(
                    SecurityIssue(
                        ip=ip,
                        issue=f"Multiple failed login attempts ({c} failures)",
                        severity=sev,
                        recommendation="Block the IP, enable rate limiting, and review authentication logs/users.",
                        attack_type="Brute Force",
                        source=event.source,
                        timestamp=event.timestamp,
                        details={"failed_login_count": c},
                    )
                )

        # Repeated requests to same path (access logs)
        path = event.metadata.get("path")
        if isinstance(path, str) and path:
            key = (ip, path)
            c = ctx["requests"].get(key, 0) + 1
            ctx["requests"][key] = c
            if c in (50, 100, 250):
                sev = Severity.MEDIUM if c == 50 else Severity.HIGH
                if c >= 250:
                    sev = Severity.CRITICAL
                issues.append(
                    SecurityIssue(
                        ip=ip,
                        issue=f"Unusual repeated requests to {path} ({c} hits)",
                        severity=sev,
                        recommendation="Check for automated scanning; apply rate limiting/WAF rules and consider blocking.",
                        attack_type="Scanning / Enumeration",
                        source=event.source,
                        timestamp=event.timestamp,
                        details={"path": path, "request_count": c},
                    )
                )

        return issues

    rules.append(Rule("bruteforce_and_repeats", brute_force_and_repeats))

    def sensitive_paths(event: LogEvent, ctx: Dict[str, Any]) -> List[SecurityIssue]:
        path = event.metadata.get("path")
        if not isinstance(path, str) or not path:
            return []

        p = path.lower()
        markers = (
            "/admin",
            "/wp-admin",
            "/phpmyadmin",
            "/.git",
            "/.env",
            "/server-status",
            "/actuator",
            "/debug",
            "/config",
        )
        if not any(m in p for m in markers):
            return []

        return [
            SecurityIssue(
                ip=event.ip,
                issue=f"Access to potentially sensitive path {path}",
                severity=Severity.MEDIUM,
                recommendation="Restrict access (auth/IP allowlist), disable debug endpoints, and review request legitimacy.",
                attack_type="Reconnaissance",
                source=event.source,
                timestamp=event.timestamp,
                details={"path": path},
            )
        ]

    rules.append(Rule("sensitive_paths", sensitive_paths))

    def payload_attacks(event: LogEvent, ctx: Dict[str, Any]) -> List[SecurityIssue]:
        """
        Detect payload-based attacks (SQLi, XSS, path traversal) in paths, query strings,
        and generic raw log lines.
        """
        issues: List[SecurityIssue] = []

        # Try to get a textual representation of the request / payload.
        candidates: List[str] = []
        path = event.metadata.get("path")
        if isinstance(path, str):
            candidates.append(path)
        # JSON / app logs may contain request/params/body fields.
        for key in ("url", "request", "query", "params", "body", "message"):
            val = event.metadata.get(key)
            if isinstance(val, str):
                candidates.append(val)

        candidates.append(event.raw)
        text = " ".join(candidates)

        # SQL Injection
        if any(p.search(text) for p in _SQLI_PATTERNS):
            issues.append(
                SecurityIssue(
                    ip=event.ip,
                    issue="Potential SQL injection payload detected",
                    severity=Severity.CRITICAL,
                    recommendation=(
                        "Review the affected endpoint and parameters for SQL injection vulnerabilities. "
                        "Use parameterized queries/ORM, strict input validation, and WAF rules."
                    ),
                    attack_type="SQL Injection",
                    source=event.source,
                    timestamp=event.timestamp,
                    details={"sample": text[:256]},
                )
            )

        # XSS
        if any(p.search(text) for p in _XSS_PATTERNS):
            issues.append(
                SecurityIssue(
                    ip=event.ip,
                    issue="Potential XSS (cross-site scripting) payload detected",
                    severity=Severity.HIGH,
                    recommendation=(
                        "Ensure all user-controlled data is properly escaped/encoded in HTML, "
                        "implement Content Security Policy (CSP), and sanitize inputs."
                    ),
                    attack_type="XSS",
                    source=event.source,
                    timestamp=event.timestamp,
                    details={"sample": text[:256]},
                )
            )

        # Path traversal
        if any(p.search(text) for p in _PATH_TRAVERSAL_PATTERNS):
            issues.append(
                SecurityIssue(
                    ip=event.ip,
                    issue="Potential path traversal attempt detected",
                    severity=Severity.HIGH,
                    recommendation=(
                        "Normalize and validate file paths, restrict access to allowed directories only, "
                        "and avoid constructing paths directly from user input."
                    ),
                    attack_type="Path Traversal",
                    source=event.source,
                    timestamp=event.timestamp,
                    details={"sample": text[:256]},
                )
            )

        return issues

    rules.append(Rule("payload_attacks", payload_attacks))

    return rules


# ==========================
# Analyzer + reporting
# ==========================


class LogAnalyzer:
    def __init__(self, rule_engine: Optional[RuleEngine] = None) -> None:
        self.rule_engine = rule_engine or RuleEngine(default_rules())

    def analyze_stream(
        self,
        parser: BaseLogParser,
        lines: Iterable[str],
        *,
        max_issues: int = 2000,
        filters: Optional[Dict[str, Any]] = None,
        counters: Optional[Dict[str, int]] = None,
    ) -> List[SecurityIssue]:
        """
        Stream events through the rule engine and return a bounded list of issues.

        `counters` is a dict that will be updated with legacy summary counts.
        """
        filters = filters or {}
        counters = counters if counters is not None else {}

        def issue_allowed(issue: SecurityIssue) -> bool:
            ip_f = filters.get("ip")
            if ip_f and issue.ip != ip_f:
                return False
            sev_f = filters.get("severity")
            if sev_f and issue.severity.value != sev_f and issue.severity != sev_f:
                return False
            start = filters.get("start_time")
            end = filters.get("end_time")
            if issue.timestamp and isinstance(start, datetime) and issue.timestamp < start:
                return False
            if issue.timestamp and isinstance(end, datetime) and issue.timestamp > end:
                return False
            return True

        # Severity ranking for aggregation (highest wins)
        severity_rank = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        def counted_events() -> Iterator[LogEvent]:
            for evt in parser.parse_stream(lines):
                # Legacy counters (for existing UI)
                counters["total_events"] = counters.get("total_events", 0) + 1
                lower = evt.raw.lower()
                if "error" in lower:
                    counters["errors"] = counters.get("errors", 0) + 1
                if "warning" in lower:
                    counters["warnings"] = counters.get("warnings", 0) + 1
                if any(p.search(lower) for p in _FAILED_LOGIN_PATTERNS):
                    counters["failed_logins"] = counters.get("failed_logins", 0) + 1
                yield evt

        aggregated: Dict[Tuple[Optional[str], str], SecurityIssue] = {}

        for issue in self.rule_engine.analyze(counted_events()):
            if not issue_allowed(issue):
                continue

            # Aggregate by (ip, issue text) so we don't output duplicates.
            key = (issue.ip, issue.issue)
            existing = aggregated.get(key)
            if existing is None:
                aggregated[key] = issue
            else:
                # Increase count and keep the highest severity.
                new_count = (existing.count or 1) + 1
                best_sev = (
                    issue.severity
                    if severity_rank[issue.severity] > severity_rank[existing.severity]
                    else existing.severity
                )
                aggregated[key] = SecurityIssue(
                    ip=existing.ip,
                    issue=existing.issue,
                    severity=best_sev,
                    recommendation=existing.recommendation,
                    source=existing.source,
                    timestamp=existing.timestamp or issue.timestamp,
                    details=existing.details or issue.details,
                    count=new_count,
                )

            if len(aggregated) >= max_issues:
                break

        return list(aggregated.values())

    @staticmethod
    def dashboard_summary(issues: List[SecurityIssue]) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        by_ip: Dict[str, int] = {}
        for i in issues:
            by_sev[i.severity.value] = by_sev.get(i.severity.value, 0) + 1
            ip = i.ip or "unknown"
            by_ip[ip] = by_ip.get(ip, 0) + 1
        return {"total_issues": len(issues), "by_severity": by_sev, "by_ip": by_ip}


# ==========================
# Public API (used by Flask route)
# ==========================


def analyze_log(
    file_path: Union[str, Path],
    *,
    source: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
    max_issues: int = 2000,
) -> Dict[str, Any]:
    """
    Analyze a log file and return a JSON-serializable report.

    Returns (always):
      - total_events, errors, warnings, failed_logins   (legacy counters for UI)

    Also returns:
      - issues: list of structured findings
      - summary_dashboard: counts by severity / IP
      - meta: detected_source, max_issues, truncated

    `source` can be forced: "nmap" | "web" | "json" | "plain"
    """
    path = Path(file_path)
    if not path.is_file():
        return {
            "total_events": 0,
            "errors": 0,
            "warnings": 0,
            "failed_logins": 0,
            "issues": [],
            "summary_dashboard": {"total_issues": 0, "by_severity": {}, "by_ip": {}},
            "meta": {"detected_source": None, "truncated": False, "max_issues": max_issues},
        }

    # Sample a small window for detection, then chain it back to keep streaming.
    sample_lines: List[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for _ in range(60):
            line = f.readline()
            if not line:
                break
            sample_lines.append(line)

    factory = ParserFactory()
    detected_parser = factory.detect(sample_lines, file_suffix=path.suffix)

    if source:
        src = source.lower()
        if src == "nmap":
            parser: BaseLogParser = NmapLogParser()
        elif src in ("apache", "nginx", "web"):
            parser = WebServerLogParser("web")
        elif src == "json":
            parser = JSONLinesParser("json")
        else:
            parser = PlainTextParser(src)
        detected_source = src
    else:
        parser = detected_parser
        detected_source = getattr(parser, "source_name", "plain")

    counters: Dict[str, int] = {"total_events": 0, "errors": 0, "warnings": 0, "failed_logins": 0}
    analyzer = LogAnalyzer()

    def line_stream() -> Iterator[str]:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            yield from chain(sample_lines, f)

    issues = analyzer.analyze_stream(
        parser,
        line_stream(),
        max_issues=max_issues,
        filters=filters,
        counters=counters,
    )
    truncated = len(issues) >= max_issues

    return {
        **counters,
        "issues": [i.to_json() for i in issues],
        "summary_dashboard": analyzer.dashboard_summary(issues),
        "meta": {"detected_source": detected_source, "truncated": truncated, "max_issues": max_issues},
    }


def monitor_log_file(
    file_path: Union[str, Path],
    *,
    source: str = "plain",
    poll_interval: float = 1.0,
) -> Iterator[SecurityIssue]:
    """
    Real-time monitoring (tail-like). Yields SecurityIssue objects as they are detected.
    Suitable for background workers or SSE/WebSocket streaming.
    """
    path = Path(file_path)
    if not path.is_file():
        return iter(())  # type: ignore[return-value]

    if source == "nmap":
        parser: BaseLogParser = NmapLogParser()
    elif source in ("apache", "nginx", "web"):
        parser = WebServerLogParser("web")
    elif source == "json":
        parser = JSONLinesParser("json")
    else:
        parser = PlainTextParser(source)

    engine = RuleEngine(default_rules())
    context: Dict[str, Any] = {"failed_logins": {}, "requests": {}, "open_ports": {}}

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                f.seek(where)
                continue
            evt = parser.parse_line(line.rstrip("\n"))
            if not evt:
                continue
            for rule in engine.rules:
                for issue in rule.apply(evt, context):
                    yield issue

