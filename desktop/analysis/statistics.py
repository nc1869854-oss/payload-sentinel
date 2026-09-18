"""
analysis/statistics.py

Session statistics — calculated from the in-memory packet list.

These functions answer questions like:
    • What protocols are most common?
    • Which IPs are talking the most?
    • How much traffic per minute?
    • What are the largest payloads?

All calculations are deterministic — no AI, no external services.
"""

from collections import defaultdict, Counter
import datetime


def calculate_protocol_distribution(packets: list[dict]) -> list[dict]:
    """
    Count how many packets use each protocol.

    Returns a sorted list like:
        [{"protocol": "TCP", "count": 820, "percent": 73.2}, ...]
    """
    if not packets:
        return []

    counts = Counter(p.get("protocol", "UNKNOWN") for p in packets)
    total  = len(packets)

    result = []
    for protocol, count in counts.most_common():
        result.append({
            "protocol": protocol,
            "count":    count,
            "percent":  round(100.0 * count / total, 1),
        })
    return result


def calculate_direction_distribution(packets: list[dict]) -> dict:
    """
    Split packets into INCOMING, OUTGOING, INTERNAL, UNKNOWN counts.

    Returns a dict like:
        {"INCOMING": 412, "OUTGOING": 598, "INTERNAL": 22, "UNKNOWN": 5}
    """
    counts = defaultdict(int)
    for p in packets:
        direction = p.get("direction", "UNKNOWN")
        counts[direction] += 1

    # Ensure all keys always present
    for key in ("INCOMING", "OUTGOING", "INTERNAL", "UNKNOWN"):
        if key not in counts:
            counts[key] = 0

    return dict(counts)


def calculate_top_ips(packets: list[dict], top_n: int = 10) -> dict:
    """
    Find the most active source and destination IP addresses.

    Returns:
        {
            "top_sources":      [{"ip": "...", "count": N}, ...],
            "top_destinations": [{"ip": "...", "count": N}, ...],
        }
    """
    src_counts  = Counter(p["src_ip"] for p in packets if p.get("src_ip"))
    dst_counts  = Counter(p["dst_ip"] for p in packets if p.get("dst_ip"))

    return {
        "top_sources":      [
            {"ip": ip, "count": c} for ip, c in src_counts.most_common(top_n)
        ],
        "top_destinations": [
            {"ip": ip, "count": c} for ip, c in dst_counts.most_common(top_n)
        ],
    }


def calculate_top_ports(packets: list[dict], top_n: int = 10) -> list[dict]:
    """
    Find the most frequently contacted destination ports.

    Returns:
        [{"port": 443, "count": 320, "service": "HTTPS"}, ...]
    """
    dst_ports = Counter(
        p["dst_port"] for p in packets
        if p.get("dst_port") is not None
    )

    result = []
    for port, count in dst_ports.most_common(top_n):
        result.append({
            "port":    port,
            "count":   count,
            "service": _common_port_name(port),
        })
    return result


def calculate_traffic_over_time(packets: list[dict], bucket_seconds: int = 10) -> list[dict]:
    """
    Bin packets into time buckets to show traffic rate over time.

    bucket_seconds — width of each time slice (default 10s)

    Returns:
        [{"time": "HH:MM:SS", "packets": N, "bytes": B}, ...]
    """
    if not packets:
        return []

    # Parse timestamps and group by time bucket
    buckets: dict[str, dict] = {}

    for p in packets:
        raw_time = p.get("capture_time", "")
        if not raw_time:
            continue

        try:
            dt = datetime.datetime.fromisoformat(raw_time)
        except ValueError:
            continue

        # Snap to the nearest bucket boundary
        total_seconds = int(dt.timestamp())
        bucket_start  = total_seconds - (total_seconds % bucket_seconds)
        key = datetime.datetime.fromtimestamp(bucket_start).strftime("%H:%M:%S")

        if key not in buckets:
            buckets[key] = {"time": key, "packets": 0, "bytes": 0}

        buckets[key]["packets"] += 1
        buckets[key]["bytes"]   += p.get("packet_size", 0)

    # Return sorted by time
    return sorted(buckets.values(), key=lambda b: b["time"])


def calculate_payload_statistics(packets: list[dict]) -> dict:
    """
    Aggregate payload-specific statistics.

    Returns:
        {
            "total_payload_bytes": N,
            "packets_with_payload": N,
            "packets_without_payload": N,
            "largest_payload": N,
            "average_payload": N,
        }
    """
    payload_sizes = [p["payload_size"] for p in packets if p.get("payload_size", 0) > 0]

    return {
        "total_payload_bytes":     sum(payload_sizes),
        "packets_with_payload":    len(payload_sizes),
        "packets_without_payload": len(packets) - len(payload_sizes),
        "largest_payload":         max(payload_sizes) if payload_sizes else 0,
        "average_payload":         int(sum(payload_sizes) / len(payload_sizes))
                                   if payload_sizes else 0,
    }


def build_session_summary(packets: list[dict], flows: list[dict]) -> dict:
    """
    Build a complete statistics summary for a session.
    Used by the statistics panel, the dashboard, and the report builder.
    """
    total_bytes = sum(p.get("packet_size", 0) for p in packets)

    return {
        "total_packets":        len(packets),
        "total_bytes":          total_bytes,
        "total_flows":          len(flows),
        "protocol_distribution": calculate_protocol_distribution(packets),
        "direction_distribution": calculate_direction_distribution(packets),
        "top_ips":              calculate_top_ips(packets),
        "top_ports":            calculate_top_ports(packets),
        "traffic_over_time":    calculate_traffic_over_time(packets),
        "payload_stats":        calculate_payload_statistics(packets),
    }


def _common_port_name(port: int) -> str:
    """Return the common service name for well-known port numbers."""
    well_known = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
        443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
        587: "SMTP/TLS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "ORACLE", 3306: "MYSQL", 3389: "RDP",
        5432: "POSTGRES", 5900: "VNC", 6379: "REDIS", 8080: "HTTP-ALT",
        8443: "HTTPS-ALT", 27017: "MONGODB",
    }
    return well_known.get(port, "")
