"""
reports/report_builder.py

Assemble all session data into a single structured report dict.

Every export format (HTML, PDF, CSV, JSON) calls build_report_data()
first to get this dict, then formats it as needed. This means all
formats are guaranteed to contain the same underlying data.

The caller passes a sections dict to control which sections appear:
    {
        "executive_summary": True,
        "capture_info": True,
        "traffic_stats": True,
        ...
    }
"""

import datetime
from evidence.database import (
    get_session, get_packets, get_flows, get_alerts,
    get_notes,
)
from evidence.sessions import format_duration
from analysis.statistics import build_session_summary
from analysis.rules import run_all_rules, severity_sort_key
from investigation.timeline import build_timeline_events


# All available report sections with their display names
ALL_SECTIONS = {
    "executive_summary":   "Executive Summary",
    "capture_info":        "Capture Information",
    "traffic_stats":       "Traffic Statistics",
    "protocol_distribution": "Protocol Distribution",
    "top_destinations":    "Top Destinations",
    "top_sources":         "Top Sources",
    "flow_summary":        "Flow Summary",
    "findings":            "Findings",
    "alerts":              "Alerts",
    "timeline":            "Timeline",
    "payload_stats":       "Payload Statistics",
    "analyst_notes":       "Analyst Notes",
    "evidence_hashes":     "Evidence Hashes",
}


def build_report_data(session_id: str,
                      sections: dict,
                      analyst_name: str = "Analyst",
                      packets: list[dict] = None,
                      flows: list[dict] = None) -> dict:
    """
    Build a complete report data structure for one session.

    Parameters
    ----------
    session_id   : session to report on
    sections     : dict mapping section key → bool (include or not)
    analyst_name : name to appear in the report header
    packets      : live in-memory packets (if capture window is open)
                   falls back to DB if None
    flows        : live in-memory flows (if available)
    """
    # ── Load session metadata ─────────────────────────────────────────────────
    session = get_session(session_id)
    if not session:
        raise ValueError(f"Session '{session_id}' not found in database.")

    created_at = session.get("created_at", "")
    closed_at  = session.get("closed_at", "")

    # Calculate session duration
    if created_at:
        try:
            start = datetime.datetime.fromisoformat(created_at)
            end   = (datetime.datetime.fromisoformat(closed_at)
                     if closed_at else datetime.datetime.now())
            duration_str = format_duration(start, end)
        except ValueError:
            duration_str = "—"
    else:
        duration_str = "—"

    # ── Load packets / flows (prefer live data, fall back to DB) ─────────────
    if packets is None:
        packets = get_packets(session_id, limit=50000)
    if flows is None:
        flows = get_flows(session_id)

    # ── Run analysis ──────────────────────────────────────────────────────────
    stats    = build_session_summary(packets, flows)
    findings = run_all_rules(packets, flows)
    findings.sort(key=severity_sort_key)

    db_alerts = get_alerts(session_id)
    db_notes  = get_notes(session_id)

    timeline_events = build_timeline_events(packets) if sections.get("timeline") else []

    # ── Severity breakdown for executive summary ──────────────────────────────
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # ── Assemble the report dict ──────────────────────────────────────────────
    report = {
        # ── Meta ─────────────────────────────────────────────────────────────
        "meta": {
            "report_title":    "Network Forensics Report",
            "application":     "Payload Capture Suite",
            "investigation_id": session_id,
            "analyst":         analyst_name,
            "generated_at":    datetime.datetime.now().isoformat(timespec="seconds"),
            "report_version":  "1.0",
        },

        # ── Session ───────────────────────────────────────────────────────────
        "session": {
            "session_id":  session_id,
            "created_at":  created_at,
            "closed_at":   closed_at,
            "duration":    duration_str,
            "interface":   session.get("interface", "—"),
            "capture_mode": session.get("capture_mode", "LIVE"),
            "analyst":     session.get("analyst", analyst_name),
        },

        # ── High-level counts for executive summary ───────────────────────────
        "summary_counts": {
            "total_packets":  stats["total_packets"],
            "total_bytes":    stats["total_bytes"],
            "total_flows":    stats["total_flows"],
            "total_findings": len(findings),
            "total_alerts":   len(db_alerts),
            "total_notes":    len(db_notes),
            "severity_counts": sev_counts,
        },

        # ── Traffic statistics ────────────────────────────────────────────────
        "traffic": {
            "protocol_distribution": stats["protocol_distribution"],
            "direction_distribution": stats["direction_distribution"],
            "top_sources":      stats["top_ips"]["top_sources"],
            "top_destinations": stats["top_ips"]["top_destinations"],
            "top_ports":        stats["top_ports"],
            "traffic_over_time": stats["traffic_over_time"],
        },

        # ── Flows ─────────────────────────────────────────────────────────────
        "flows": flows[:500],   # cap for large sessions

        # ── Findings (from rule engine) ───────────────────────────────────────
        "findings": findings,

        # ── Alerts (saved to DB) ──────────────────────────────────────────────
        "alerts": db_alerts,

        # ── Timeline ──────────────────────────────────────────────────────────
        "timeline": timeline_events[:1000],   # cap for readability

        # ── Payload statistics ────────────────────────────────────────────────
        "payload_stats": stats["payload_stats"],

        # ── Analyst notes ─────────────────────────────────────────────────────
        "notes": db_notes,

        # ── Which sections to include ─────────────────────────────────────────
        "sections": sections,
    }

    return report
