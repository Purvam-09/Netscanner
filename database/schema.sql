-- NetScanner Database Schema
-- SQLite-compatible
-- Tables: users, scans, scheduled_scans, cve_cache

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT    NOT NULL UNIQUE,
  email        TEXT    NOT NULL UNIQUE,
  password_hash TEXT   NOT NULL,
  role         TEXT    NOT NULL DEFAULT 'user',       -- 'user' | 'admin'
  avatar_color TEXT    NOT NULL DEFAULT '#00ff9f',    -- cyberpunk accent
  notify_email INTEGER NOT NULL DEFAULT 0,            -- email notifications
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  last_login   TEXT
);

-- ── Scans ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id          INTEGER NOT NULL,
  target           TEXT    NOT NULL,
  scan_type        TEXT    NOT NULL DEFAULT 'tcp-connect',
  ports            TEXT    NOT NULL DEFAULT '1-1000',
  status           TEXT    NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
  progress         INTEGER NOT NULL DEFAULT 0,         -- 0-100 %
  results_json     TEXT,                               -- { open_ports, hosts_scanned, ... }
  error_message    TEXT,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  completed_at     TEXT,
  duration_seconds REAL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);

-- ── Scheduled Scans ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scheduled_scans (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  target     TEXT    NOT NULL,
  scan_type  TEXT    NOT NULL DEFAULT 'tcp-connect',
  ports      TEXT    NOT NULL DEFAULT '1-1000',
  cron_expr  TEXT    NOT NULL,                         -- e.g. "0 */6 * * *"
  label      TEXT,                                     -- human-readable name
  enabled    INTEGER NOT NULL DEFAULT 1,
  last_run   TEXT,
  next_run   TEXT,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scheduled_user ON scheduled_scans(user_id);

-- ── CVE Cache ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_cache (
  service    TEXT PRIMARY KEY,                         -- e.g. "http", "ssh"
  cves_json  TEXT    NOT NULL,                         -- JSON array of CVEs
  fetched_at TEXT    NOT NULL DEFAULT (datetime('now'))
);