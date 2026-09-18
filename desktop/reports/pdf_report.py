"""
reports/pdf_report.py

Generate a professional PDF forensics report using ReportLab.

Falls back gracefully if reportlab is not installed — the rest of
the application continues to work; only PDF export is disabled.
"""

import pathlib
from evidence.sessions import format_bytes

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ─── Colour palette (matches the dark UI theme) ───────────────────────────────
C_BG        = colors.HexColor("#0d1117")
C_CARD      = colors.HexColor("#161b22")
C_ACCENT    = colors.HexColor("#58a6ff")
C_TEXT      = colors.HexColor("#e6edf3")
C_DIM       = colors.HexColor("#8b949e")
C_SUCCESS   = colors.HexColor("#3fb950")
C_WARNING   = colors.HexColor("#d29922")
C_DANGER    = colors.HexColor("#f85149")
C_MUTED     = colors.HexColor("#30363d")
C_WHITE     = colors.white

SEVERITY_COLORS_PDF = {
    "CRITICAL": colors.HexColor("#ff0000"),
    "HIGH":     colors.HexColor("#f85149"),
    "MEDIUM":   colors.HexColor("#d29922"),
    "LOW":      colors.HexColor("#3fb950"),
    "INFO":     colors.HexColor("#79c0ff"),
}


def generate_pdf_report(report_data: dict,
                        output_path: str | pathlib.Path) -> str:
    """
    Write a PDF report to output_path.
    Returns the absolute path as a string.
    Raises ImportError if reportlab is not installed.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF export.\n"
            "Install it with:  pip install reportlab"
        )

    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=20*mm,  rightMargin=20*mm,
        topMargin=20*mm,   bottomMargin=20*mm,
        title=f"Network Forensics Report — {report_data['session']['session_id']}",
        author=report_data["meta"]["analyst"],
    )

    styles = _build_styles()
    story  = _build_story(report_data, styles)

    doc.build(story)
    return str(path)


# ─── Style definitions ────────────────────────────────────────────────────────

def _build_styles() -> dict:
    base = getSampleStyleSheet()

    def style(name, parent="Normal", **kwargs):
        return ParagraphStyle(name, parent=base[parent], **kwargs)

    return {
        "title": style("title",
            fontSize=22, textColor=C_ACCENT, spaceAfter=4,
            fontName="Helvetica-Bold"),

        "subtitle": style("subtitle",
            fontSize=11, textColor=C_DIM, spaceAfter=16,
            fontName="Helvetica"),

        "section_head": style("section_head",
            fontSize=10, textColor=C_DIM, spaceAfter=6, spaceBefore=14,
            fontName="Helvetica-Bold", textTransform="uppercase",
            borderPadding=(0, 0, 4, 0)),

        "body": style("body",
            fontSize=9, textColor=C_TEXT, spaceAfter=4,
            fontName="Helvetica", leading=14),

        "body_dim": style("body_dim",
            fontSize=9, textColor=C_DIM, spaceAfter=4,
            fontName="Helvetica", leading=14),

        "mono": style("mono",
            fontSize=8, textColor=C_TEXT,
            fontName="Courier", leading=12),

        "mono_green": style("mono_green",
            fontSize=8, textColor=C_SUCCESS,
            fontName="Courier", leading=12),

        "bullet": style("bullet",
            fontSize=9, textColor=C_TEXT, spaceAfter=2,
            fontName="Helvetica", leftIndent=12, leading=13),

        "finding_title": style("finding_title",
            fontSize=10, textColor=C_TEXT, spaceAfter=3,
            fontName="Helvetica-Bold"),

        "rec": style("rec",
            fontSize=9, textColor=C_ACCENT, spaceAfter=4,
            fontName="Helvetica-Oblique", leading=13),

        "footer": style("footer",
            fontSize=8, textColor=C_DIM, alignment=TA_CENTER),
    }


# ─── Story builder ────────────────────────────────────────────────────────────

def _build_story(report_data: dict, styles: dict) -> list:
    """Build the complete list of ReportLab flowables."""
    story  = []
    meta   = report_data["meta"]
    session= report_data["session"]
    counts = report_data["summary_counts"]
    secs   = report_data["sections"]

    def HR():
        return HRFlowable(width="100%", thickness=0.5,
                          color=C_MUTED, spaceAfter=8, spaceBefore=4)

    def SP(h=6):
        return Spacer(1, h)

    # ── Cover block ───────────────────────────────────────────────────────────
    story.append(Paragraph("PAYLOAD CAPTURE SUITE", styles["title"]))
    story.append(Paragraph("Network Forensics Report", styles["subtitle"]))
    story.append(HR())

    # Meta table
    meta_data = [
        ["Investigation ID", session["session_id"],
         "Analyst",          meta["analyst"]],
        ["Capture Date",     session["created_at"][:10],
         "Duration",         session["duration"]],
        ["Interface",        session["interface"],
         "Report Generated", meta["generated_at"][:19]],
    ]
    meta_table = Table(meta_data, colWidths=[38*mm, 55*mm, 38*mm, 55*mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("TEXTCOLOR",  (0,0), (0,-1), C_DIM),
        ("TEXTCOLOR",  (2,0), (2,-1), C_DIM),
        ("TEXTCOLOR",  (1,0), (1,-1), C_TEXT),
        ("TEXTCOLOR",  (3,0), (3,-1), C_TEXT),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",   (2,0), (2,-1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING",    (0,0), (-1,-1), 2),
    ]))
    story.append(meta_table)
    story.append(SP(12))

    # ── Overview cards ────────────────────────────────────────────────────────
    card_data = [[
        _card_cell("PACKETS",  f"{counts['total_packets']:,}", styles),
        _card_cell("FLOWS",    f"{counts['total_flows']:,}", styles),
        _card_cell("FINDINGS", f"{counts['total_findings']:,}", styles),
        _card_cell("BYTES",    format_bytes(counts["total_bytes"]), styles),
    ]]
    card_table = Table(card_data, colWidths=[42*mm]*4)
    card_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_CARD),
        ("BOX",           (0,0), (0,0),  0.5, C_MUTED),
        ("BOX",           (1,0), (1,0),  0.5, C_MUTED),
        ("BOX",           (2,0), (2,0),  0.5, C_MUTED),
        ("BOX",           (3,0), (3,0),  0.5, C_MUTED),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ]))
    story.append(card_table)
    story.append(SP(12))

    # ── Executive Summary ─────────────────────────────────────────────────────
    if secs.get("executive_summary"):
        story.append(Paragraph("Executive Summary", styles["section_head"]))
        story.append(HR())
        sev = counts["severity_counts"]
        sev_text = ", ".join(
            f"{n} {level}"
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            for n in [sev.get(level, 0)]
            if n > 0
        ) or "none"

        story.append(Paragraph(
            f"Session <b>{session['session_id']}</b> was captured on "
            f"{session['created_at'][:10]} over {session['duration']}. "
            f"A total of <b>{counts['total_packets']:,} packets</b> were "
            f"analysed across <b>{counts['total_flows']:,} flows</b>. "
            f"The rule engine identified <b>{counts['total_findings']} "
            f"finding(s)</b>: {sev_text}.",
            styles["body"]
        ))
        story.append(Paragraph(
            "Findings are heuristic observations requiring analyst review. "
            "Severity indicates investigation priority, not certainty of threat.",
            styles["body_dim"]
        ))
        story.append(SP())

    # ── Traffic Statistics ────────────────────────────────────────────────────
    if secs.get("traffic_stats"):
        story.append(Paragraph("Traffic Statistics", styles["section_head"]))
        story.append(HR())
        traffic = report_data["traffic"]
        dd      = traffic["direction_distribution"]
        total   = max(counts["total_packets"], 1)

        rows = [
            ["Metric", "Value"],
            ["Total Packets",    f"{counts['total_packets']:,}"],
            ["Total Bytes",      format_bytes(counts["total_bytes"])],
            ["Total Flows",      f"{counts['total_flows']:,}"],
            ["Incoming Packets", f"{dd.get('INCOMING',0):,}  "
                                 f"({100*dd.get('INCOMING',0)//total}%)"],
            ["Outgoing Packets", f"{dd.get('OUTGOING',0):,}  "
                                 f"({100*dd.get('OUTGOING',0)//total}%)"],
            ["Internal Packets", f"{dd.get('INTERNAL',0):,}  "
                                 f"({100*dd.get('INTERNAL',0)//total}%)"],
        ]
        story.append(_simple_table(rows, styles))
        story.append(SP())

    # ── Protocol Distribution ─────────────────────────────────────────────────
    if secs.get("protocol_distribution"):
        story.append(Paragraph("Protocol Distribution", styles["section_head"]))
        story.append(HR())
        protos = report_data["traffic"]["protocol_distribution"]
        rows   = [["Protocol", "Packets", "Percent"]] + [
            [p["protocol"], f"{p['count']:,}", f"{p['percent']}%"]
            for p in protos[:15]
        ]
        story.append(_simple_table(rows, styles))
        story.append(SP())

    # ── Top Sources ───────────────────────────────────────────────────────────
    if secs.get("top_sources"):
        story.append(Paragraph("Top Source IPs", styles["section_head"]))
        story.append(HR())
        rows = [["IP Address", "Packets"]] + [
            [s["ip"], f"{s['count']:,}"]
            for s in report_data["traffic"]["top_sources"][:15]
        ]
        story.append(_simple_table(rows, styles))
        story.append(SP())

    # ── Top Destinations ──────────────────────────────────────────────────────
    if secs.get("top_destinations"):
        story.append(Paragraph("Top Destination IPs", styles["section_head"]))
        story.append(HR())
        rows = [["IP Address", "Packets"]] + [
            [d["ip"], f"{d['count']:,}"]
            for d in report_data["traffic"]["top_destinations"][:15]
        ]
        story.append(_simple_table(rows, styles))
        story.append(SP())

    # ── Flow Summary ──────────────────────────────────────────────────────────
    if secs.get("flow_summary"):
        flows = report_data["flows"]
        story.append(Paragraph(
            f"Flow Summary (top 30 of {len(flows)})",
            styles["section_head"]
        ))
        story.append(HR())
        rows = [["Protocol", "Source", "Destination", "Pkts", "Bytes", "Risk"]]
        for flow in flows[:30]:
            src = f"{flow.get('src_ip','?')}:{flow.get('src_port','?')}"
            dst = f"{flow.get('dst_ip','?')}:{flow.get('dst_port','?')}"
            rows.append([
                flow.get("protocol", "?"),
                src, dst,
                f"{flow.get('packet_count',0):,}",
                format_bytes(flow.get("byte_count", 0)),
                flow.get("risk_level", "NONE"),
            ])
        story.append(_simple_table(rows, styles,
                                   col_widths=[20*mm, 45*mm, 45*mm,
                                               18*mm, 22*mm, 18*mm]))
        story.append(SP())

    # ── Findings ──────────────────────────────────────────────────────────────
    if secs.get("findings"):
        findings = report_data["findings"]
        story.append(Paragraph(
            f"Findings ({len(findings)})", styles["section_head"]
        ))
        story.append(HR())

        if not findings:
            story.append(Paragraph("No findings generated.", styles["body_dim"]))
        else:
            for finding in findings:
                sev       = finding.get("severity", "INFO")
                sev_color = SEVERITY_COLORS_PDF.get(sev, C_DIM)
                evidence  = finding.get("evidence", [])
                if isinstance(evidence, str):
                    evidence = [evidence]

                block = []
                block.append(Paragraph(
                    f'<font color="#{_hex(sev_color)}">{sev}</font>'
                    f'  —  {finding.get("title", "")}',
                    styles["finding_title"]
                ))
                block.append(Paragraph(
                    finding.get("description", ""), styles["body_dim"]
                ))
                for bullet in evidence:
                    block.append(Paragraph(f"• {bullet}", styles["bullet"]))
                block.append(Paragraph(
                    f"Recommendation: {finding.get('recommendation', '')}",
                    styles["rec"]
                ))
                block.append(SP(4))
                story.append(KeepTogether(block))

    # ── Timeline ──────────────────────────────────────────────────────────────
    if secs.get("timeline"):
        events = report_data["timeline"]
        story.append(Paragraph(
            f"Timeline ({len(events)} events, showing first 150)",
            styles["section_head"]
        ))
        story.append(HR())

        rows = [["Time", "Type", "Description"]]
        for ev in events[:150]:
            rows.append([
                ev["display_time"],
                ev["event_type"],
                ev["description"][:80],
            ])
        story.append(_simple_table(rows, styles,
                                   col_widths=[20*mm, 20*mm, 128*mm]))
        story.append(SP())

    # ── Payload Statistics ────────────────────────────────────────────────────
    if secs.get("payload_stats"):
        ps = report_data["payload_stats"]
        story.append(Paragraph("Payload Statistics", styles["section_head"]))
        story.append(HR())
        rows = [
            ["Metric", "Value"],
            ["Total Payload Bytes",     format_bytes(ps.get("total_payload_bytes", 0))],
            ["Packets with Payload",    f"{ps.get('packets_with_payload', 0):,}"],
            ["Packets without Payload", f"{ps.get('packets_without_payload', 0):,}"],
            ["Largest Payload",         format_bytes(ps.get("largest_payload", 0))],
            ["Average Payload",         format_bytes(ps.get("average_payload", 0))],
        ]
        story.append(_simple_table(rows, styles))
        story.append(SP())

    # ── Analyst Notes ─────────────────────────────────────────────────────────
    if secs.get("analyst_notes"):
        notes = report_data["notes"]
        story.append(Paragraph(
            f"Analyst Notes ({len(notes)})", styles["section_head"]
        ))
        story.append(HR())
        if not notes:
            story.append(Paragraph("No notes recorded.", styles["body_dim"]))
        else:
            for note in notes:
                story.append(Paragraph(
                    f"<b>{note.get('created_at','')[:19]}</b>  "
                    f"| {note.get('target_type','')} "
                    f"| {str(note.get('target_id',''))[:40]}",
                    styles["body_dim"]
                ))
                story.append(Paragraph(
                    note.get("content", ""), styles["body"]
                ))
                story.append(SP(4))

    # ── Evidence Hashes ───────────────────────────────────────────────────────
    if secs.get("evidence_hashes"):
        from evidence.database import get_connection
        conn = get_connection()
        file_rows = conn.execute(
            "SELECT * FROM evidence_files WHERE session_id = ? ORDER BY created_at",
            (session["session_id"],)
        ).fetchall()
        conn.close()

        story.append(Paragraph("Evidence Files & Hashes",
                                styles["section_head"]))
        story.append(HR())

        if not file_rows:
            story.append(Paragraph(
                "No evidence files recorded.", styles["body_dim"]
            ))
        else:
            for row in file_rows:
                story.append(Paragraph(
                    f"<b>{row['filename']}</b>  [{row['file_type']}]",
                    styles["body"]
                ))
                story.append(Paragraph(
                    f"SHA-256: {row['sha256'] or '(not calculated)'}",
                    styles["mono_green"]
                ))
                story.append(Paragraph(row["file_path"], styles["body_dim"]))
                story.append(SP(4))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(SP(12))
    story.append(HR())
    story.append(Paragraph(
        f"Generated by Payload Capture Suite  ·  {meta['generated_at'][:19]}  ·  "
        "Findings are heuristic observations — verify independently before acting.",
        styles["footer"]
    ))

    return story


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _simple_table(rows: list, styles: dict,
                  col_widths: list = None) -> Table:
    """Build a standard dark-themed data table."""
    n_cols = len(rows[0]) if rows else 1

    if col_widths is None:
        total_width = 168 * mm   # A4 minus margins
        col_widths = [total_width / n_cols] * n_cols

    # Wrap cell text in Paragraph for word-wrap
    wrapped = []
    for i, row in enumerate(rows):
        style = styles["mono"] if i > 0 else styles["body_dim"]
        wrapped.append([
            Paragraph(str(cell), style) for cell in row
        ])

    table = Table(wrapped, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        # Header row
        ("BACKGROUND",    (0,0), (-1,0),  C_CARD),
        ("TEXTCOLOR",     (0,0), (-1,0),  C_DIM),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0),  8),
        # Data rows — alternating backgrounds
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_BG, C_CARD]),
        ("FONTNAME",      (0,1), (-1,-1), "Courier"),
        ("FONTSIZE",      (0,1), (-1,-1), 8),
        # Grid
        ("LINEBELOW",     (0,0), (-1,0),  0.5, C_MUTED),
        ("LINEBELOW",     (0,1), (-1,-1), 0.25, C_MUTED),
        # Padding
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    return table


def _card_cell(label: str, value: str, styles: dict) -> list:
    """A metric card as a table cell (list of flowables)."""
    return [
        Paragraph(label,
                  ParagraphStyle("cl", fontName="Helvetica-Bold",
                                 fontSize=8, textColor=C_DIM)),
        Paragraph(value,
                  ParagraphStyle("cv", fontName="Helvetica-Bold",
                                 fontSize=18, textColor=C_ACCENT)),
    ]


def _hex(color) -> str:
    """Convert a ReportLab color to a 6-char hex string (without #)."""
    try:
        r = int(color.red * 255)
        g = int(color.green * 255)
        b = int(color.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "8b949e"
