"""
reports/csv_report.py

Export session data to CSV files.

Produces multiple CSV files bundled into a single zip archive:
  packets.csv
  flows.csv
  findings.csv
  timeline.csv
  notes.csv
"""

import csv
import io
import pathlib
import zipfile


def generate_csv_export(report_data: dict,
                        output_path: str | pathlib.Path) -> str:
    """
    Write a zip archive containing CSV files for each data type.
    Returns the absolute path of the zip file.
    """
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(str(path), "w", zipfile.ZIP_DEFLATED) as zf:
        # ── Flows ─────────────────────────────────────────────────────────────
        zf.writestr("flows.csv", _flows_csv(report_data["flows"]))

        # ── Findings ──────────────────────────────────────────────────────────
        zf.writestr("findings.csv", _findings_csv(report_data["findings"]))

        # ── Timeline ──────────────────────────────────────────────────────────
        zf.writestr("timeline.csv", _timeline_csv(report_data["timeline"]))

        # ── Notes ─────────────────────────────────────────────────────────────
        zf.writestr("notes.csv", _notes_csv(report_data["notes"]))

        # ── Session metadata ──────────────────────────────────────────────────
        zf.writestr("session_info.csv", _session_csv(report_data))

    return str(path)


def _flows_csv(flows: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "flow_id", "protocol", "src_ip", "src_port",
        "dst_ip", "dst_port", "packet_count", "byte_count",
        "first_seen", "last_seen", "direction", "risk_level",
    ])
    for f in flows:
        writer.writerow([
            f.get("flow_id", ""),
            f.get("protocol", ""),
            f.get("src_ip", ""),
            f.get("src_port", ""),
            f.get("dst_ip", ""),
            f.get("dst_port", ""),
            f.get("packet_count", 0),
            f.get("byte_count", 0),
            f.get("first_seen", ""),
            f.get("last_seen", ""),
            f.get("direction", ""),
            f.get("risk_level", ""),
        ])
    return out.getvalue()


def _findings_csv(findings: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "severity", "title", "description",
        "evidence", "recommendation",
        "related_ip", "related_flow", "created_at",
    ])
    for f in findings:
        evidence = f.get("evidence", [])
        if isinstance(evidence, list):
            evidence = " | ".join(evidence)
        writer.writerow([
            f.get("severity", ""),
            f.get("title", ""),
            f.get("description", ""),
            evidence,
            f.get("recommendation", ""),
            f.get("related_ip", ""),
            f.get("related_flow", ""),
            f.get("created_at", ""),
        ])
    return out.getvalue()


def _timeline_csv(events: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "time", "display_time", "event_type",
        "description", "related_ip",
        "related_flow", "related_packet",
    ])
    for ev in events:
        writer.writerow([
            ev.get("time", ""),
            ev.get("display_time", ""),
            ev.get("event_type", ""),
            ev.get("description", ""),
            ev.get("related_ip", ""),
            ev.get("related_flow", ""),
            ev.get("related_packet", ""),
        ])
    return out.getvalue()


def _notes_csv(notes: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["created_at", "target_type", "target_id", "content"])
    for n in notes:
        writer.writerow([
            n.get("created_at", ""),
            n.get("target_type", ""),
            n.get("target_id", ""),
            n.get("content", ""),
        ])
    return out.getvalue()


def _session_csv(report_data: dict) -> str:
    out    = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["field", "value"])
    session= report_data["session"]
    counts = report_data["summary_counts"]
    for key, val in {
        "session_id":    session["session_id"],
        "created_at":    session["created_at"],
        "closed_at":     session.get("closed_at", ""),
        "duration":      session["duration"],
        "interface":     session["interface"],
        "analyst":       session["analyst"],
        "total_packets": counts["total_packets"],
        "total_flows":   counts["total_flows"],
        "total_bytes":   counts["total_bytes"],
        "total_findings":counts["total_findings"],
    }.items():
        writer.writerow([key, val])
    return out.getvalue()
