# NetScanner — Project Notes

## Overview

NetScanner is a Flask-based cybersecurity web application for network discovery and port scanning.

## Features

- **Dashboard** — Overview and quick actions
- **Host Discovery** — ICMP ping sweep (CIDR or IP range)
- **Port Scanner** — TCP Connect, TCP SYN, UDP scans
- **Results** — Scan history with filters, export (CSV/PDF), delete
- **Scheduler** — Cron-based scheduled scans
- **Import** — Host Discovery → Port Scan (single or multi-target)

## Run

```bash
python run.py
```

Open http://localhost:5000/login

## Structure

- `backend/` — Flask app, blueprints, services, models, utils, templates
- `frontend/assets/` — CSS, JS (served at `/assets/`)
- `database/` — SQLite schema and migrations
