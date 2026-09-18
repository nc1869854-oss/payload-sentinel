"""
flows/tracker.py

Track network flows.

A "flow" is a conversation between two endpoints — all packets sharing
the same (protocol, src_ip, src_port, dst_ip, dst_port) tuple, in
either direction, are grouped into one flow.

This transforms the raw packet stream into something more investigable:
instead of 10,000 individual packets, an analyst sees 40 conversations.
"""

from collections import defaultdict


class FlowTracker:
    """
    Maintains a dict of active flows in memory.

    Call update(parsed_packet) for each packet as it arrives.
    Call get_all_flows() to retrieve the current flow table.
    """

    def __init__(self):
        # flow_id → flow dict
        self._flows: dict[str, dict] = {}

    def update(self, parsed_packet: dict) -> None:
        """
        Update the flow table with a new packet.

        Creates a new flow entry if this is the first packet for that
        conversation, or updates the existing entry.

        We always recompute the canonical flow_id here so that both
        directions of a conversation map to the same flow — even if
        the packet dict's flow_id field was built without sorting.
        """
        from packets.parser import _make_flow_id as _canonical
        flow_id = _canonical(
            parsed_packet.get("src_ip"),
            parsed_packet.get("src_port"),
            parsed_packet.get("dst_ip"),
            parsed_packet.get("dst_port"),
            parsed_packet.get("protocol", "UNKNOWN"),
        )
        # Also update the packet dict so downstream users see the canonical id
        parsed_packet["flow_id"] = flow_id

        if not flow_id or flow_id == "UNKNOWN":
            return

        if flow_id not in self._flows:
            # New flow — create it
            self._flows[flow_id] = {
                "flow_id":      flow_id,
                "protocol":     parsed_packet.get("protocol", "UNKNOWN"),
                "src_ip":       parsed_packet.get("src_ip"),
                "src_port":     parsed_packet.get("src_port"),
                "dst_ip":       parsed_packet.get("dst_ip"),
                "dst_port":     parsed_packet.get("dst_port"),
                "packet_count": 0,
                "byte_count":   0,
                "first_seen":   parsed_packet.get("capture_time"),
                "last_seen":    parsed_packet.get("capture_time"),
                "direction":    parsed_packet.get("direction", "UNKNOWN"),
                "risk_level":   "NONE",
            }

        # Update the existing flow
        flow = self._flows[flow_id]
        flow["packet_count"] += 1
        flow["byte_count"]   += parsed_packet.get("packet_size", 0)
        flow["last_seen"]     = parsed_packet.get("capture_time")

    def get_all_flows(self) -> list[dict]:
        """
        Return all flows as a list, sorted by packet count descending.
        The busiest flows appear first — usually the most interesting.
        """
        return sorted(
            self._flows.values(),
            key=lambda f: f["packet_count"],
            reverse=True
        )

    def get_flow(self, flow_id: str) -> dict | None:
        """Return a single flow by ID, or None if not found."""
        return self._flows.get(flow_id)

    def flow_count(self) -> int:
        """Return the number of unique flows seen so far."""
        return len(self._flows)

    def clear(self) -> None:
        """Remove all flows (called when capture is cleared)."""
        self._flows.clear()

    def get_flows_for_ip(self, ip_address: str) -> list[dict]:
        """Return all flows involving a specific IP address."""
        return [
            flow for flow in self._flows.values()
            if flow.get("src_ip") == ip_address
            or flow.get("dst_ip") == ip_address
        ]

    def get_statistics(self) -> dict:
        """
        Return aggregate statistics across all flows.
        Used by the statistics subsystem and dashboard counters.
        """
        if not self._flows:
            return {
                "total_flows":   0,
                "total_bytes":   0,
                "top_talkers":   [],
                "top_ports":     [],
            }

        total_bytes = sum(f["byte_count"] for f in self._flows.values())

        # Count bytes per IP (counting both sides of each flow)
        ip_bytes: dict[str, int] = defaultdict(int)
        port_counts: dict[int, int] = defaultdict(int)

        for flow in self._flows.values():
            if flow.get("src_ip"):
                ip_bytes[flow["src_ip"]] += flow["byte_count"] // 2
            if flow.get("dst_ip"):
                ip_bytes[flow["dst_ip"]] += flow["byte_count"] // 2
            if flow.get("dst_port"):
                port_counts[flow["dst_port"]] += 1

        top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports   = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_flows": len(self._flows),
            "total_bytes": total_bytes,
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
            "top_ports":   [{"port": p, "count": c} for p, c in top_ports],
        }
