-- Add scan_mode for Nmap-style modes: fast, top_1000, full, stealth_connect, normal
ALTER TABLE scans ADD COLUMN scan_mode TEXT NOT NULL DEFAULT 'normal';
