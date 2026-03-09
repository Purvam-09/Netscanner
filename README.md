# NetScanner

Web-based network scanner with Nmap-inspired scan modes. **No Nmap binary** — custom Python socket-based engine.

## Quick Start

```bash
pip install -r requirements.txt
python run.py
# Open http://localhost:5000/login
```

## Scan Modes

| Mode | Port Source | Nmap-style |
|------|-------------|------------|
| **normal** | User-entered ports only | `-sT -p <ports>` |
| **stealth_connect** | User-entered ports only | `-sT -T2 -p <ports>` |
| **fast** | Top 100 predefined ports | `--top-ports 100` |
| **top_1000** | Ports 1–1000 | `--top-ports 1000` |
| **full** | All 65535 ports | `-p-` |

**Rules:** Predefined modes (fast, top_1000, full) never use user port input. User modes (normal, stealth_connect) never mix with predefined ports.

## Scan Types

- **TCP Connect** — Full handshake, works without root
- **TCP SYN** — Half-open scan (Scapy + root on Linux; else falls back to connect)
- **UDP** — Datagram probe
- **Ping Sweep** — Host discovery only (TCP probes to common ports). **Does not scan ports.** Nmap equivalent: `nmap -sn`

## Project Structure

```
netscanner/
├── run.py                 # Entry point
├── backend/
│   ├── blueprints/        # API routes (auth, scans, export, scheduler, etc.)
│   ├── services/
│   │   ├── scanner_engine/  # Scanning logic (see below)
│   │   ├── scan_worker.py   # Background scan execution
│   │   ├── cve_lookup.py    # NVD CVE lookup
│   │   └── export_service.py
│   └── utils/validators.py
└── database/
    ├── schema.sql
    └── migrations/
```

**Learn the codebase**: See [PROJECT_CODE_GUIDE.md](PROJECT_CODE_GUIDE.md) for a file-by-file guide.

## Scanner Engine

See `backend/services/scanner_engine/README.md` for scan mode mapping, port logic, and limitations.

## Known Limitations

- IPv4 only (no IPv6)
- No raw ICMP ping
- SYN scan requires Linux + root + Scapy
- Service detection: banner parsing only (no Nmap probe DB)

## Shutdown

Ctrl+C stops the server. Daemon threads (scan worker, scheduler) exit with the process.
