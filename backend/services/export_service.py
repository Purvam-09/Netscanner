"""
backend/services/export_service.py
------------------------------------
Generates CSV and PDF export files from scan results.

Usage:
    csv_bytes = generate_csv(scan_row, results_data)
    pdf_bytes = generate_pdf(scan_row, results_data)
"""
import csv
import io
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# ── CSV ───────────────────────────────────────────────────────────────────────

def generate_csv(scan: dict, results: dict | None) -> bytes:
    """
    Returns UTF-8 encoded CSV bytes.
    For port scans: open ports with service/version/banner.
    For ping scans: host list only.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    scan_id    = scan.get("id", "")
    target     = scan.get("target", "")
    scan_type  = scan.get("scan_type", "")
    scanned_at = scan.get("completed_at") or scan.get("created_at") or ""

    if scan_type in ("ping", "host-discovery"):
        writer.writerow(["scan_id", "target", "scan_type", "host", "scanned_at"])
        hosts_up = (results or {}).get("hosts_up", [])
        if not hosts_up:
            writer.writerow([scan_id, target, scan_type, "N/A", scanned_at])
        else:
            for host in hosts_up:
                writer.writerow([scan_id, target, scan_type, host, scanned_at])
    else:
        writer.writerow([
            "scan_id", "target", "scan_type",
            "port", "protocol", "service", "version", "banner", "state",
            "scanned_at",
        ])
        open_ports = (results or {}).get("open_ports", [])
        if not open_ports:
            writer.writerow([scan_id, target, scan_type, "N/A", "", "", "", "", "no open ports", scanned_at])
        else:
            for p in open_ports:
                writer.writerow([
                    scan_id, target, scan_type,
                    p.get("port", ""), p.get("protocol", "tcp"),
                    p.get("service", ""), p.get("version", ""), p.get("banner", ""),
                    p.get("state", "open"),
                    scanned_at,
                ])

    return buf.getvalue().encode("utf-8")


# ── PDF ───────────────────────────────────────────────────────────────────────

def generate_pdf(scan: dict, results: dict | None) -> bytes:
    """
    Returns PDF bytes for a single scan report.
    Uses reportlab for a clean, professional layout.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as e:
        raise RuntimeError("reportlab is required for PDF export. Run: pip install reportlab") from e

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    dark   = colors.HexColor("#0d1117")
    green  = colors.HexColor("#00ff9f")
    grey   = colors.HexColor("#8b949e")

    title_style = ParagraphStyle(
        "Title", parent=styles["Heading1"],
        fontSize=18, textColor=dark, spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        "Sub", parent=styles["Normal"],
        fontSize=9, textColor=grey, spaceAfter=12,
    )
    label_style = ParagraphStyle(
        "Label", parent=styles["Normal"],
        fontSize=10, textColor=dark, spaceBefore=6,
    )

    story = []

    # Header
    story.append(Paragraph("NetScanner — Scan Report", title_style))
    story.append(Paragraph(
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        sub_style,
    ))
    story.append(Spacer(1, 0.3 * cm))

    # Metadata table
    scan_type = scan.get("scan_type", "")
    open_ports = (results or {}).get("open_ports", [])
    hosts_up   = (results or {}).get("hosts_up", [])
    meta_data  = [
        ["Scan ID",        str(scan.get("id", ""))],
        ["Target",         scan.get("target", "")],
        ["Scan Type",      scan_type],
        ["Status",         scan.get("status", "").upper()],
        ["Duration",       f"{scan.get('duration_seconds', '–')} s"],
        ["Completed",      scan.get("completed_at", "")[:19] if scan.get("completed_at") else "–"],
    ]
    if scan_type in ("ping", "host-discovery"):
        meta_data.extend([
            ["Port Range",     "N/A (host discovery only)"],
            ["Hosts Up",       str(len(hosts_up))],
        ])
    else:
        meta_data.extend([
            ["Port Range",     scan.get("ports", "")],
            ["Open Ports",     str(len(open_ports))],
        ])

    meta_table = Table(meta_data, colWidths=[5 * cm, 11 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#f6f8fa")),
        ("TEXTCOLOR",   (0, 0), (0, -1), dark),
        ("TEXTCOLOR",   (1, 0), (1, -1), dark),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.white, colors.HexColor("#f6f8fa")]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # Results table
    if scan_type in ("ping", "host-discovery"):
        story.append(Paragraph("Host Discovery — Live Hosts", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * cm))
        if not hosts_up:
            story.append(Paragraph("No live hosts found.", label_style))
        else:
            host_data = [["Host"]]
            for h in hosts_up:
                host_data.append([h])
            host_table = Table(host_data, colWidths=[6 * cm])
            host_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), dark),
                ("TEXTCOLOR", (0, 0), (-1, 0), green),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(host_table)
    else:
        story.append(Paragraph("Open Ports", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * cm))
        if not open_ports:
            story.append(Paragraph("No open ports found.", label_style))
        else:
            port_data = [["Port", "Protocol", "Service", "Version", "Banner", "State"]]
            for p in open_ports:
                port_data.append([
                    str(p.get("port", "")),
                    p.get("protocol", "tcp"),
                    p.get("service", ""),
                    (p.get("version") or "")[:30],
                    (p.get("banner") or "")[:50],
                    p.get("state", "open"),
                ])

            port_table = Table(
                port_data,
                colWidths=[1.5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm, 4 * cm, 1.5 * cm],
            )
            port_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), dark),
                ("TEXTCOLOR",     (0, 0), (-1, 0), green),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
                ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("WORDWRAP",      (3, 1), (3, -1), True),
            ]))
            story.append(port_table)

    # Error note if any
    if scan.get("error_message"):
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            f"<b>Error:</b> {scan['error_message']}", label_style
        ))

    doc.build(story)
    return buf.getvalue()