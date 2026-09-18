"""
investigation/timeline.py

Build a chronological sequence of significant network events from captured packets.

The timeline turns raw packet data into analyst-readable events like:
    "DNS query for example.com"
    "TCP connection established to 8.8.8.8:443"
    "TLS communication observed"
    "Connection closed"

This gives analysts a story of what happened, not just a table of numbers.
"""

import datetime
from collections import defaultdict


# Event type labels — used for filtering in the timeline UI
EVENT_TYPE_DNS      = "DNS"
EVENT_TYPE_TCP      = "TCP"
EVENT_TYPE_UDP      = "UDP"
EVENT_TYPE_TLS      = "TLS"
EVENT_TYPE_HTTP     = "HTTP"
EVENT_TYPE_ICMP     = "ICMP"
EVENT_TYPE_FLOW     = "FLOW"
EVENT_TYPE_ALERT    = "ALERT"
EVENT_TYPE_GENERAL  = "GENERAL"


def build_timeline_events(packets: list[dict]) -> list[dict]:
    """
    Produce a list of significant timeline events from a packet list.

    Returns events sorted by time, oldest first.

    Each event dict contains:
        time          — ISO timestamp string
        display_time  — HH:MM:SS for display
        event_type    — one of the EVENT_TYPE_* constants above
        description   — human-readable single-line description
        related_ip    — associated IP (for filtering)
        related_flow  — flow_id if applicable
        related_packet— packet_number if applicable
    """
    events: list[dict] = []

    # Track which flows we've already created a FLOW_START event for
    seen_flows: set[str] = set()

    # Track first DNS query per domain (avoid duplicate events)
    seen_dns_queries: set[str] = set()

    for packet in packets:
        protocol = packet.get("protocol", "")
        src_ip   = packet.get("src_ip")
        dst_ip   = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        src_port = packet.get("src_port")
        flow_id  = packet.get("flow_id")
        time_str = packet.get("capture_time", "")
        pkt_num  = packet.get("packet_number")

        # ── DNS events ───────────────────────────────────────────────────────
        if packet.get("is_dns"):
            query = packet.get("dns_query")
            if query and query not in seen_dns_queries:
                seen_dns_queries.add(query)
                events.append(_make_event(
                    time_str, EVENT_TYPE_DNS,
                    f"DNS query  →  {query}",
                    related_ip=dst_ip, related_flow=flow_id, related_packet=pkt_num
                ))

            response = packet.get("dns_response")
            if response:
                query_name = packet.get("dns_query", "")
                events.append(_make_event(
                    time_str, EVENT_TYPE_DNS,
                    f"DNS response  ←  {query_name}  →  {response}",
                    related_ip=src_ip, related_flow=flow_id, related_packet=pkt_num
                ))

        # ── New flow events ───────────────────────────────────────────────────
        elif flow_id and flow_id != "UNKNOWN" and flow_id not in seen_flows:
            seen_flows.add(flow_id)

            # TCP connection started
            if protocol == "TCP":
                if dst_port in (443, 8443):
                    desc = (f"TCP connection  →  {dst_ip}:{dst_port}  "
                            f"(TLS/HTTPS expected)")
                    etype = EVENT_TYPE_TLS
                elif dst_port in (80, 8080):
                    desc  = f"TCP connection  →  {dst_ip}:{dst_port}  (HTTP)"
                    etype = EVENT_TYPE_HTTP
                else:
                    desc  = (f"TCP connection  →  {dst_ip}:{dst_port}  "
                             f"from  {src_ip}:{src_port}")
                    etype = EVENT_TYPE_TCP

                events.append(_make_event(
                    time_str, etype, desc,
                    related_ip=dst_ip, related_flow=flow_id, related_packet=pkt_num
                ))

            # UDP flow started
            elif protocol == "UDP":
                events.append(_make_event(
                    time_str, EVENT_TYPE_UDP,
                    f"UDP flow  →  {dst_ip}:{dst_port}  from  {src_ip}:{src_port}",
                    related_ip=dst_ip, related_flow=flow_id, related_packet=pkt_num
                ))

            # ICMP
            elif protocol == "ICMP":
                events.append(_make_event(
                    time_str, EVENT_TYPE_ICMP,
                    f"ICMP traffic  →  {dst_ip}  from  {src_ip}",
                    related_ip=dst_ip, related_flow=flow_id, related_packet=pkt_num
                ))

    # Sort by time
    events.sort(key=lambda e: e["time"])
    return events


def _make_event(time_str: str, event_type: str, description: str,
                related_ip: str = None, related_flow: str = None,
                related_packet: int = None) -> dict:
    """Helper to construct a timeline event dict."""
    # Format display time as HH:MM:SS
    display_time = time_str[11:19] if len(time_str) >= 19 else time_str

    return {
        "time":           time_str,
        "display_time":   display_time,
        "event_type":     event_type,
        "description":    description,
        "related_ip":     related_ip,
        "related_flow":   related_flow,
        "related_packet": related_packet,
    }


def filter_events(events: list[dict], event_type: str = "ALL") -> list[dict]:
    """
    Return only events matching the given type.
    Passing "ALL" returns everything.
    """
    if event_type == "ALL":
        return events
    return [e for e in events if e["event_type"] == event_type]
