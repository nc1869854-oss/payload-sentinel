"""
investigation/ip.py

IP address investigation utilities.

All lookups are performed locally using the Python standard library:
  - ipaddress  : classification (private, loopback, multicast, etc.)
  - socket     : reverse DNS lookup

IMPORTANT: Reverse DNS is a clue, not authoritative ownership proof.
Anyone can set any PTR record. We never automatically label an IP as
"safe" or "malicious" based solely on rDNS or classification.
"""

import ipaddress
import socket
import datetime
from collections import defaultdict


# ─── IP Classification ────────────────────────────────────────────────────────

def classify_ip(ip_str: str) -> dict:
    """
    Return classification information about an IP address.

    Returns a dict with keys:
        address       : the IP string as given
        version       : 4 or 6
        ip_type       : PUBLIC | PRIVATE | LOOPBACK | MULTICAST |
                        LINK_LOCAL | RESERVED | UNKNOWN
        is_private    : bool
        is_loopback   : bool
        is_multicast  : bool
        is_global     : bool
        network_class : A / B / C / Multicast / Other  (IPv4 only)
        description   : human-readable classification sentence
    """
    result = {
        "address":       ip_str,
        "version":       None,
        "ip_type":       "UNKNOWN",
        "is_private":    False,
        "is_loopback":   False,
        "is_multicast":  False,
        "is_global":     False,
        "network_class": "—",
        "description":   "",
    }

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        result["description"] = f"'{ip_str}' is not a valid IP address."
        return result

    result["version"]    = addr.version
    result["is_private"] = addr.is_private
    result["is_loopback"]= addr.is_loopback
    result["is_multicast"]= addr.is_multicast
    result["is_global"]  = addr.is_global

    # Determine primary type label
    if addr.is_loopback:
        result["ip_type"]     = "LOOPBACK"
        result["description"] = "Loopback address — traffic stays on this host."
    elif addr.is_link_local:
        result["ip_type"]     = "LINK_LOCAL"
        result["description"] = "Link-local address — valid only on the local network segment."
    elif addr.is_multicast:
        result["ip_type"]     = "MULTICAST"
        result["description"] = "Multicast address — sent to a group of receivers."
    elif addr.is_private:
        result["ip_type"]     = "PRIVATE"
        result["description"] = "Private (RFC 1918) address — not routable on the public internet."
    elif addr.is_reserved:
        result["ip_type"]     = "RESERVED"
        result["description"] = "Reserved address range."
    else:
        result["ip_type"]     = "PUBLIC"
        result["description"] = "Publicly routable address."

    # IPv4 network class (informational only)
    if addr.version == 4:
        first_octet = int(str(addr).split(".")[0])
        if first_octet < 128:
            result["network_class"] = "A"
        elif first_octet < 192:
            result["network_class"] = "B"
        elif first_octet < 224:
            result["network_class"] = "C"
        elif first_octet < 240:
            result["network_class"] = "Multicast (D)"
        else:
            result["network_class"] = "Reserved (E)"

    return result


def reverse_dns_lookup(ip_str: str, timeout_seconds: float = 2.0) -> str:
    """
    Attempt a reverse DNS (PTR) lookup for the given IP.

    Returns the hostname string, or an empty string on failure.

    NOTE: PTR records are set by the IP owner and are not verified.
    A PTR record saying "google.com" does not prove the IP belongs
    to Google. Always treat rDNS as a clue, not proof.
    """
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_seconds)
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(original_timeout)


# ─── Session IP aggregation ───────────────────────────────────────────────────

def build_ip_summary(ip_str: str, packets: list[dict],
                     flows: list[dict]) -> dict:
    """
    Aggregate all session data related to a specific IP address.

    Returns a dict the UI can display directly.
    """
    # Packets where this IP appears as source or destination
    related_packets = [
        p for p in packets
        if p.get("src_ip") == ip_str or p.get("dst_ip") == ip_str
    ]

    # Flows where this IP appears
    related_flows = [
        f for f in flows
        if f.get("src_ip") == ip_str or f.get("dst_ip") == ip_str
    ]

    total_bytes = sum(p.get("packet_size", 0) for p in related_packets)
    total_payload = sum(p.get("payload_size", 0) for p in related_packets)

    # Find first and last times this IP was seen
    times = [
        p["capture_time"] for p in related_packets
        if p.get("capture_time")
    ]
    first_seen = min(times)[11:19] if times else "—"
    last_seen  = max(times)[11:19] if times else "—"

    # Outbound vs inbound packet split for this IP
    outbound = sum(1 for p in related_packets if p.get("src_ip") == ip_str)
    inbound  = sum(1 for p in related_packets if p.get("dst_ip") == ip_str)

    # Ports this IP communicated on
    dst_ports = sorted({
        p.get("dst_port") for p in related_packets
        if p.get("dst_port") is not None
    })

    # Protocols seen
    protocols = sorted({
        p.get("protocol") for p in related_packets
        if p.get("protocol")
    })

    return {
        "address":          ip_str,
        "packet_count":     len(related_packets),
        "flow_count":       len(related_flows),
        "total_bytes":      total_bytes,
        "total_payload":    total_payload,
        "outbound_packets": outbound,
        "inbound_packets":  inbound,
        "first_seen":       first_seen,
        "last_seen":        last_seen,
        "protocols":        ", ".join(protocols) if protocols else "—",
        "dst_ports":        dst_ports[:20],     # cap at 20 for display
        "related_flows":    related_flows,
        "related_packets":  related_packets[:100],  # cap for display
    }


def get_all_ip_addresses(packets: list[dict]) -> list[str]:
    """
    Return a sorted, deduplicated list of all IP addresses seen in a
    packet list (both source and destination).
    """
    seen: set[str] = set()

    for p in packets:
        if p.get("src_ip"):
            seen.add(p["src_ip"])
        if p.get("dst_ip"):
            seen.add(p["dst_ip"])

    return sorted(seen, key=lambda ip: _ip_sort_key(ip))


def _ip_sort_key(ip_str: str):
    """Sort IPs numerically rather than lexicographically."""
    try:
        return int(ipaddress.ip_address(ip_str))
    except ValueError:
        return 0
