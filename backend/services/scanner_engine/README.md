# Scanner Engine (Nmap-Inspired)

Custom Python scanning engine. **No Nmap binary is called**; behaviour is inspired by Nmap concepts for documentation and UX.

## Why socket-based by default

- **Portability**: TCP connect (`-sT`) works on all platforms without root.
- **Safety**: No raw packets; no admin/root required.
- **Educational**: Clear, auditable code; no external process dependency.

## Scan type ↔ Nmap mapping

| Scan type     | Nmap option | Behaviour |
|---------------|-------------|-----------|
| tcp-connect   | `-sT`       | Full TCP handshake via `socket.connect()`. Default. |
| tcp-syn       | `-sS`       | SYN scan when Scapy + root available; else falls back to connect. |
| udp           | `-sU`-like  | UDP probe (send datagram; timeout ⇒ open\|filtered). No ICMP parsing. |
| ping          | Host discovery | No raw ICMP; uses DNS + TCP checks to decide “host up”. |

## Scan mode ↔ Nmap mapping

| scan_mode       | Nmap equivalent   | Port set / behaviour |
|-----------------|-------------------|------------------------|
| fast            | `--top-ports 100` | **Top 100 common ports only.** User port range is ignored. |
| top_1000        | `--top-ports 1000` | **Ports 1–1000 (predefined).** User port range is ignored. |
| full            | `-p-`             | **All ports 1–65535.** User port range is ignored. |
| normal          | `-sT -p <ports>`  | **User port range only.** No predefined ports. |
| stealth_connect | `-sT -T2 -p <ports>` | **User port range only.** Connect with T2 timing; no banner read. |

### Port logic (CRITICAL)

| Mode | Port Source |
|------|-------------|
| normal, stealth_connect | User-entered ports ONLY |
| fast, top_1000, full | Predefined ports ONLY (never mix) |

Backend never "guesses" ports. Frontend disables port input for predefined modes.

## Service/version detection ↔ Nmap

| Feature        | Nmap | This engine |
|----------------|------|-------------|
| Service probe | `-sV` | Banner read + regex; optional HTTP/FTP probes. |
| Version        | Yes  | Parsed from banners (SSH, HTTP, FTP, etc.). |
| No Nmap binary| —    | All logic in Python; no external calls. |

## Timing

- **T2** (polite): longer random delays between probes.
- **T3** (normal): default delays.
- **T4** (aggressive): minimal delay.

Implemented in `timing_engine` (randomized port order, inter-probe delay).

## Limitations vs real Nmap

- **No raw SYN**: SYN scan requires Scapy + root (Linux); otherwise we use connect.
- **No ICMP ping**: “Ping” is host discovery via DNS/TCP only.
- **UDP**: No ICMP unreachable parsing; we report open|filtered.
- **Service detection**: Banner/regex only; no Nmap-style probe DB.
- **OS fingerprinting**: Not implemented.
- **Scripting**: No NSE equivalent.

## Architecture

| Module | Responsibility |
|--------|----------------|
| `config.py` | Port lists, timing profiles, SCAN_MODE_CONFIG |
| `port_parser.py` | Parse user port input — single source of truth |
| `results.py` | Normalize output format |
| `connect_scan.py` | TCP connect scan |
| `service_detection.py` | Banner parsing, version regex |
| `timing_engine.py` | Port randomization, T2/T3/T4 delays |
| `host_discovery.py` | Pre-scan host discovery (DNS/TCP) |
| `syn_scan.py` | Optional Scapy SYN; graceful fallback |
