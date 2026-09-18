"""
reports/html_report.py

Generate a self-contained HTML forensics report.

The output is a single .html file with embedded CSS — no external
dependencies — so it can be shared as a standalone document and
opened in any browser without an internet connection.

The report follows the section structure defined in report_builder.py.
"""

import pathlib
from evidence.sessions import format_bytes


# ─── CSS stylesheet (embedded in the HTML) ───────────────────────────────────

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0d1117;
    color: #e6edf3;
    font-size: 13px;
    line-height: 1.6;
}
.page { max-width: 1100px; margin: 0 auto; padding: 40px 32px; }

/* Header */
.report-header {
    border-bottom: 2px solid #30363d;
    padding-bottom: 24px;
    margin-bottom: 32px;
}
.report-header h1 { font-size: 28px; color: #58a6ff; letter-spacing: 2px; }
.report-header .subtitle { color: #8b949e; font-size: 13px; margin-top: 4px; }
.meta-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-top: 20px;
}
.meta-item label { color: #8b949e; font-size: 11px; text-transform: uppercase; }
.meta-item span  { display: block; color: #e6edf3; font-size: 13px; }

/* Sections */
.section { margin-bottom: 40px; }
.section h2 {
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #8b949e;
    border-bottom: 1px solid #21262d;
    padding-bottom: 8px;
    margin-bottom: 16px;
}

/* Metric cards */
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 16px;
}
.card .label { font-size: 11px; color: #8b949e; text-transform: uppercase; }
.card .value { font-size: 26px; font-weight: 700; color: #58a6ff; margin-top: 4px; }

/* Severity badges */
.sev-CRITICAL { color: #ff0000; font-weight: 700; }
.sev-HIGH     { color: #f85149; font-weight: 700; }
.sev-MEDIUM   { color: #d29922; font-weight: 700; }
.sev-LOW      { color: #3fb950; }
.sev-INFO     { color: #79c0ff; }

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    margin-bottom: 16px;
}
th {
    background: #161b22;
    color: #8b949e;
    text-align: left;
    padding: 8px 10px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid #21262d;
}
td {
    padding: 7px 10px;
    border-bottom: 1px solid #21262d;
    color: #e6edf3;
    font-family: Consolas, monospace;
    font-size: 12px;
    vertical-align: top;
}
tr:nth-child(even) td { background: #0d1117; }
tr:nth-child(odd)  td { background: #161b22; }

/* Finding cards */
.finding {
    background: #161b22;
    border: 1px solid #21262d;
    border-left: 3px solid #d29922;
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 12px;
}
.finding.CRITICAL { border-left-color: #ff0000; }
.finding.HIGH     { border-left-color: #f85149; }
.finding.MEDIUM   { border-left-color: #d29922; }
.finding.LOW      { border-left-color: #3fb950; }
.finding.INFO     { border-left-color: #79c0ff; }

.finding-title    { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.finding-desc     { color: #8b949e; font-size: 12px; margin-bottom: 10px; line-height: 1.6; }
.finding-evidence { margin-bottom: 10px; }
.finding-evidence li { color: #e6edf3; font-size: 12px; margin-left: 16px; }
.finding-rec      {
    background: #0d1117;
    border-radius: 4px;
    padding: 8px 12px;
    color: #79c0ff;
    font-size: 12px;
    line-height: 1.5;
}

/* Timeline */
.timeline-item {
    display: grid;
    grid-template-columns: 80px 80px 1fr;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px solid #21262d;
    font-size: 12px;
}
.tl-time { color: #8b949e; font-family: Consolas, monospace; }
.tl-type { font-weight: 600; }
.tl-DNS    { color: #79c0ff; }
.tl-TCP    { color: #3fb950; }
.tl-TLS    { color: #d2a8ff; }
.tl-UDP    { color: #58a6ff; }
.tl-HTTP   { color: #ffa657; }
.tl-ICMP   { color: #f85149; }
.tl-GENERAL{ color: #8b949e; }

/* Hash block */
.hash-block {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 4px;
    padding: 12px 16px;
    font-family: Consolas, monospace;
    font-size: 11px;
    color: #3fb950;
    word-break: break-all;
    margin-bottom: 8px;
}

/* Bar chart (text-based) */
.bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; }
.bar-label { width: 100px; color: #8b949e; font-size: 11px; }
.bar-fill { height: 12px; background: #58a6ff; border-radius: 2px; min-width: 2px; }
.bar-value { color: #e6edf3; font-size: 11px; }

/* Note */
.note-block {
    background: #161b22;
    border-left: 2px solid #8b949e;
    padding: 10px 14px;
    margin-bottom: 8px;
    font-size: 12px;
    color: #8b949e;
}
.note-meta { font-size: 11px; color: #484f58; margin-bottom: 4px; }

/* Footer */
.report-footer {
    border-top: 1px solid #21262d;
    padding-top: 16px;
    margin-top: 40px;
    color: #484f58;
    font-size: 11px;
}
"""


# ─── HTML generation ──────────────────────────────────────────────────────────

def generate_html_report(report_data: dict, output_path: str | pathlib.Path) -> str:
    """
    Write a complete HTML report to output_path.
    Returns the absolute path of the written file as a string.
    """
    html = _build_html(report_data)
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return str(path)


def _build_html(report_data: dict) -> str:
    """Assemble the full HTML document from report_data."""
    meta     = report_data["meta"]
    session  = report_data["session"]
    counts   = report_data["summary_counts"]
    sections = report_data["sections"]

    parts = []

    # ── Document head ─────────────────────────────────────────────────────────
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(meta['report_title'])} — {_esc(session['session_id'])}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">
""")

    # ── Header ────────────────────────────────────────────────────────────────
    parts.append(f"""
<div class="report-header">
  <h1>PAYLOAD CAPTURE SUITE</h1>
  <div class="subtitle">Network Forensics Report</div>
  <div class="meta-grid">
    <div class="meta-item">
      <label>Investigation ID</label>
      <span>{_esc(session['session_id'])}</span>
    </div>
    <div class="meta-item">
      <label>Analyst</label>
      <span>{_esc(meta['analyst'])}</span>
    </div>
    <div class="meta-item">
      <label>Report Generated</label>
      <span>{_esc(meta['generated_at'])}</span>
    </div>
    <div class="meta-item">
      <label>Capture Date</label>
      <span>{_esc(session['created_at'][:10])}</span>
    </div>
    <div class="meta-item">
      <label>Duration</label>
      <span>{_esc(session['duration'])}</span>
    </div>
    <div class="meta-item">
      <label>Interface</label>
      <span>{_esc(session['interface'])}</span>
    </div>
  </div>
</div>
""")

    # ── Summary cards ─────────────────────────────────────────────────────────
    parts.append("""<div class="section">
<h2>Session Overview</h2>
<div class="cards">""")

    cards = [
        ("PACKETS",  f"{counts['total_packets']:,}"),
        ("FLOWS",    f"{counts['total_flows']:,}"),
        ("FINDINGS", f"{counts['total_findings']:,}"),
        ("BYTES",    format_bytes(counts['total_bytes'])),
    ]
    for label, value in cards:
        parts.append(f"""
  <div class="card">
    <div class="label">{label}</div>
    <div class="value">{_esc(value)}</div>
  </div>""")

    parts.append("</div></div>\n")

    # ── Executive Summary ─────────────────────────────────────────────────────
    if sections.get("executive_summary"):
        sev = counts["severity_counts"]
        sev_parts = []
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = sev.get(level, 0)
            if n:
                sev_parts.append(
                    f'<span class="sev-{level}">{n} {level}</span>'
                )

        parts.append(f"""<div class="section">
<h2>Executive Summary</h2>
<p>
This report covers investigation session <strong>{_esc(session['session_id'])}</strong>
captured on {_esc(session['created_at'][:10])} over a duration of
{_esc(session['duration'])}.
A total of <strong>{counts['total_packets']:,} packets</strong> were analysed,
forming <strong>{counts['total_flows']:,} network flows</strong>.
</p>
<p style="margin-top:12px">
The automated rule engine identified
<strong>{counts['total_findings']} finding(s)</strong>:
{' &nbsp;|&nbsp; '.join(sev_parts) if sev_parts else 'none'}.
</p>
<p style="margin-top:12px; color:#8b949e; font-size:12px">
<em>Note: Findings are heuristic observations requiring analyst review.
Severity indicates investigation priority, not certainty of threat.</em>
</p>
</div>
""")

    # ── Traffic Statistics ────────────────────────────────────────────────────
    if sections.get("traffic_stats"):
        traffic = report_data["traffic"]
        dd      = traffic["direction_distribution"]
        total   = max(counts["total_packets"], 1)

        parts.append("""<div class="section">
<h2>Traffic Statistics</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>""")

        rows = [
            ("Total Packets",   f"{counts['total_packets']:,}"),
            ("Total Bytes",     format_bytes(counts['total_bytes'])),
            ("Total Flows",     f"{counts['total_flows']:,}"),
            ("Incoming Packets", f"{dd.get('INCOMING', 0):,}  "
                                 f"({100*dd.get('INCOMING',0)//total}%)"),
            ("Outgoing Packets", f"{dd.get('OUTGOING', 0):,}  "
                                 f"({100*dd.get('OUTGOING',0)//total}%)"),
            ("Internal Packets", f"{dd.get('INTERNAL', 0):,}  "
                                 f"({100*dd.get('INTERNAL',0)//total}%)"),
        ]
        for label, value in rows:
            parts.append(f"<tr><td>{_esc(label)}</td><td>{_esc(value)}</td></tr>")

        parts.append("</table></div>\n")

    # ── Protocol Distribution ─────────────────────────────────────────────────
    if sections.get("protocol_distribution"):
        protos   = report_data["traffic"]["protocol_distribution"]
        max_count = max((p["count"] for p in protos), default=1)

        parts.append("""<div class="section">
<h2>Protocol Distribution</h2>""")

        for p in protos[:15]:
            bar_pct = int(200 * p["count"] / max_count)
            parts.append(f"""
<div class="bar-row">
  <div class="bar-label">{_esc(p['protocol'])}</div>
  <div class="bar-fill" style="width:{bar_pct}px"></div>
  <div class="bar-value">{p['count']:,} ({p['percent']}%)</div>
</div>""")

        parts.append("</div>\n")

    # ── Top Sources ───────────────────────────────────────────────────────────
    if sections.get("top_sources"):
        sources = report_data["traffic"]["top_sources"]
        parts.append("""<div class="section">
<h2>Top Source IPs</h2>
<table>
<tr><th>IP Address</th><th>Packets</th></tr>""")
        for s in sources[:15]:
            parts.append(
                f"<tr><td>{_esc(s['ip'])}</td><td>{s['count']:,}</td></tr>")
        parts.append("</table></div>\n")

    # ── Top Destinations ──────────────────────────────────────────────────────
    if sections.get("top_destinations"):
        dests = report_data["traffic"]["top_destinations"]
        parts.append("""<div class="section">
<h2>Top Destination IPs</h2>
<table>
<tr><th>IP Address</th><th>Packets</th></tr>""")
        for d in dests[:15]:
            parts.append(
                f"<tr><td>{_esc(d['ip'])}</td><td>{d['count']:,}</td></tr>")
        parts.append("</table></div>\n")

    # ── Flow Summary ──────────────────────────────────────────────────────────
    if sections.get("flow_summary"):
        flows = report_data["flows"]
        parts.append(f"""<div class="section">
<h2>Flow Summary (top 50 of {len(flows)})</h2>
<table>
<tr>
  <th>Protocol</th><th>Source</th><th>Destination</th>
  <th>Packets</th><th>Bytes</th><th>Risk</th>
</tr>""")
        for flow in flows[:50]:
            risk = flow.get("risk_level", "NONE")
            src = f"{flow.get('src_ip','?')}:{flow.get('src_port','?')}"
            dst = f"{flow.get('dst_ip','?')}:{flow.get('dst_port','?')}"
            parts.append(
                f"<tr>"
                f"<td>{_esc(flow.get('protocol','?'))}</td>"
                f"<td>{_esc(src)}</td>"
                f"<td>{_esc(dst)}</td>"
                f"<td>{flow.get('packet_count',0):,}</td>"
                f"<td>{format_bytes(flow.get('byte_count',0))}</td>"
                f"<td class='sev-{_esc(risk)}'>{_esc(risk)}</td>"
                f"</tr>"
            )
        parts.append("</table></div>\n")

    # ── Findings ──────────────────────────────────────────────────────────────
    if sections.get("findings"):
        findings = report_data["findings"]
        parts.append(f"""<div class="section">
<h2>Findings ({len(findings)})</h2>""")

        if not findings:
            parts.append("<p style='color:#8b949e'>No findings generated.</p>")
        else:
            for finding in findings:
                sev   = finding.get("severity", "INFO")
                evs   = finding.get("evidence", [])
                if isinstance(evs, str):
                    evs = [evs]

                bullets = "".join(f"<li>{_esc(e)}</li>" for e in evs)

                parts.append(f"""
<div class="finding {_esc(sev)}">
  <div class="finding-title">
    <span class="sev-{_esc(sev)}">{_esc(sev)}</span>
    &nbsp;—&nbsp;
    {_esc(finding.get('title', ''))}
  </div>
  <div class="finding-desc">{_esc(finding.get('description', ''))}</div>
  <div class="finding-evidence">
    <strong style="font-size:11px;color:#8b949e">EVIDENCE</strong>
    <ul>{bullets}</ul>
  </div>
  <div class="finding-rec">
    <strong style="font-size:11px">RECOMMENDATION</strong><br>
    {_esc(finding.get('recommendation', ''))}
  </div>
</div>""")

        parts.append("</div>\n")

    # ── Timeline ──────────────────────────────────────────────────────────────
    if sections.get("timeline"):
        events = report_data["timeline"]
        parts.append(f"""<div class="section">
<h2>Timeline ({len(events)} events)</h2>""")

        for ev in events[:200]:
            etype = ev.get("event_type", "GENERAL")
            parts.append(f"""
<div class="timeline-item">
  <div class="tl-time">{_esc(ev['display_time'])}</div>
  <div class="tl-type tl-{_esc(etype)}">{_esc(etype)}</div>
  <div class="tl-desc">{_esc(ev['description'])}</div>
</div>""")

        parts.append("</div>\n")

    # ── Payload Statistics ────────────────────────────────────────────────────
    if sections.get("payload_stats"):
        ps = report_data["payload_stats"]
        parts.append("""<div class="section">
<h2>Payload Statistics</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>""")
        rows = [
            ("Total Payload Bytes",     format_bytes(ps.get("total_payload_bytes", 0))),
            ("Packets with Payload",    f"{ps.get('packets_with_payload', 0):,}"),
            ("Packets without Payload", f"{ps.get('packets_without_payload', 0):,}"),
            ("Largest Payload",         format_bytes(ps.get("largest_payload", 0))),
            ("Average Payload",         format_bytes(ps.get("average_payload", 0))),
        ]
        for label, val in rows:
            parts.append(f"<tr><td>{_esc(label)}</td><td>{_esc(val)}</td></tr>")
        parts.append("</table></div>\n")

    # ── Analyst Notes ─────────────────────────────────────────────────────────
    if sections.get("analyst_notes"):
        notes = report_data["notes"]
        parts.append(f"""<div class="section">
<h2>Analyst Notes ({len(notes)})</h2>""")
        if not notes:
            parts.append("<p style='color:#8b949e'>No notes recorded.</p>")
        else:
            for note in notes:
                parts.append(f"""
<div class="note-block">
  <div class="note-meta">
    {_esc(note.get('created_at',''))}
    &nbsp;|&nbsp; {_esc(note.get('target_type',''))}
    &nbsp;|&nbsp; {_esc(str(note.get('target_id',''))[:40])}
  </div>
  {_esc(note.get('content', ''))}
</div>""")
        parts.append("</div>\n")

    # ── Evidence Hashes ───────────────────────────────────────────────────────
    if sections.get("evidence_hashes"):
        from evidence.database import get_connection
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM evidence_files WHERE session_id = ? ORDER BY created_at",
            (session["session_id"],)
        ).fetchall()
        conn.close()

        parts.append("""<div class="section">
<h2>Evidence Files &amp; Hashes</h2>""")

        if not rows:
            parts.append("<p style='color:#8b949e'>No evidence files recorded yet.</p>")
        else:
            for row in rows:
                parts.append(f"""
<div style="margin-bottom:16px">
  <div style="color:#e6edf3;margin-bottom:4px">
    <strong>{_esc(row['filename'])}</strong>
    &nbsp;<span style="color:#8b949e;font-size:11px">{_esc(row['file_type'])}</span>
  </div>
  <div class="hash-block">SHA-256: {_esc(row['sha256'] or '(not calculated)')}</div>
  <div style="color:#8b949e;font-size:11px">{_esc(row['file_path'])}</div>
</div>""")

        parts.append("</div>\n")

    # ── Footer ────────────────────────────────────────────────────────────────
    parts.append(f"""
<div class="report-footer">
  <p>Generated by Payload Capture Suite · {_esc(meta['generated_at'])}</p>
  <p style="margin-top:4px">
    Findings are heuristic observations, not conclusive determinations.
    All evidence must be independently verified before acting on it.
  </p>
</div>
</div>
</body>
</html>
""")

    return "".join(parts)


def _esc(text) -> str:
    """Escape a value for safe HTML insertion."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
