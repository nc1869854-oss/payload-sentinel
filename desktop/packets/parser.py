"""
packets/parser.py

Convert raw Scapy packet objects into clean Python dicts.

The rest of the application works with dicts — it never passes
raw Scapy objects through the queue or into the UI.
This keeps the UI code simple and makes testing easier.
"""

import datetime

# Scapy imports — wrapped in try/except so the app can show a helpful
# message if Scapy or Npcap is not installed.
try:
    from scapy.layers.inet  import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2    import Ether, ARP
    from scapy.layers.dns   import DNS, DNSQR, DNSRR
    from scapy.packet       import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def parse_packet(packet, packet_number: int, local_ip: str = "") -> dict:
    """
    Extract all useful fields from a Scapy packet into a flat dict.

    Returns a dict with consistent keys regardless of protocol.
    Missing fields are set to None or sensible defaults.

    Parameters
    ----------
    packet        : raw Scapy packet object
    packet_number : sequential number within the capture session
    local_ip      : the local machine's IP, used to determine direction
    """
    result = {
        "packet_number": packet_number,
        "capture_time":  datetime.datetime.now().isoformat(timespec="milliseconds"),
        "direction":     "UNKNOWN",
        "protocol":      "UNKNOWN",
        "src_ip":        None,
        "src_port":      None,
        "dst_ip":        None,
        "dst_port":      None,
        "packet_size":   0,
        "payload_size":  0,
        "risk_level":    "NONE",
        "flow_id":       None,
        "raw_summary":   "",
        # Extra fields used in the detail panel (not stored in DB)
        "protocol_stack": [],
        "dns_query":     None,
        "dns_response":  None,
        "is_dns":        False,
    }

    try:
        # Total packet size including all headers
        result["packet_size"] = len(bytes(packet))

        # Payload (application data) size
        result["payload_size"] = _get_payload_size(packet)

        # Build a human-readable protocol summary
        result["raw_summary"] = packet.summary()

        # ── Network layer (IP/IPv6) ──────────────────────────────────────────
        if IP in packet:
            result["src_ip"]   = packet[IP].src
            result["dst_ip"]   = packet[IP].dst
            result["protocol_stack"].append("IPv4")
        elif IPv6 in packet:
            result["src_ip"]   = packet[IPv6].src
            result["dst_ip"]   = packet[IPv6].dst
            result["protocol_stack"].append("IPv6")

        # ── Transport layer (TCP/UDP/ICMP) ───────────────────────────────────
        if TCP in packet:
            result["src_port"] = packet[TCP].sport
            result["dst_port"] = packet[TCP].dport
            result["protocol"] = "TCP"
            result["protocol_stack"].append("TCP")

        elif UDP in packet:
            result["src_port"] = packet[UDP].sport
            result["dst_port"] = packet[UDP].dport
            result["protocol"] = "UDP"
            result["protocol_stack"].append("UDP")

            # DNS travels over UDP port 53
            if DNS in packet:
                result["is_dns"] = True
                result["protocol"] = "DNS"
                result["protocol_stack"].append("DNS")
                result["dns_query"]    = _parse_dns_query(packet)
                result["dns_response"] = _parse_dns_response(packet)

        elif ICMP in packet:
            result["protocol"] = "ICMP"
            result["protocol_stack"].append("ICMP")

        elif ARP in packet:
            result["protocol"] = "ARP"
            result["protocol_stack"].append("ARP")
            # ARP uses MAC addresses, not IPs for src/dst in the traditional sense
            if result["src_ip"] is None:
                result["src_ip"] = packet[ARP].psrc
                result["dst_ip"] = packet[ARP].pdst

        # ── Application layer hints ──────────────────────────────────────────
        if result["dst_port"] == 443 or result["src_port"] == 443:
            result["protocol_stack"].append("TLS/HTTPS")
        elif result["dst_port"] == 80 or result["src_port"] == 80:
            result["protocol_stack"].append("HTTP")

        # ── Direction ────────────────────────────────────────────────────────
        result["direction"] = _determine_direction(
            result["src_ip"], result["dst_ip"], local_ip
        )

        # ── Flow ID ──────────────────────────────────────────────────────────
        result["flow_id"] = _make_flow_id(
            result["src_ip"], result["src_port"],
            result["dst_ip"], result["dst_port"],
            result["protocol"]
        )

    except Exception as e:
        # Malformed packets should not crash the application.
        # We log and return whatever we managed to extract.
        result["raw_summary"] = f"[Parse error: {e}]"

    return result


def _get_payload_size(packet) -> int:
    """
    Return the size of the application payload.

    Payload is the Raw layer — the actual data being carried,
    not the network/transport headers.
    """
    if Raw in packet:
        return len(bytes(packet[Raw].load))
    return 0


def get_payload_bytes(packet) -> bytes:
    """
    Return the raw payload bytes from a Scapy packet.
    Returns an empty bytes object if there is no payload.
    """
    if Raw in packet:
        return bytes(packet[Raw].load)
    return b""


def _determine_direction(src_ip: str, dst_ip: str, local_ip: str) -> str:
    """
    Classify traffic as INCOMING, OUTGOING, or INTERNAL.

    This is a best-effort heuristic.
    It cannot determine direction accurately without knowing the full
    network topology, but it gives analysts a useful starting point.
    """
    if not src_ip or not dst_ip:
        return "UNKNOWN"

    if local_ip:
        if src_ip == local_ip:
            return "OUTGOING"
        if dst_ip == local_ip:
            return "INCOMING"

    # If we don't know the local IP, guess based on RFC1918 private addresses
    if _is_private(src_ip) and not _is_private(dst_ip):
        return "OUTGOING"
    if not _is_private(src_ip) and _is_private(dst_ip):
        return "INCOMING"
    if _is_private(src_ip) and _is_private(dst_ip):
        return "INTERNAL"

    return "UNKNOWN"


def _is_private(ip: str) -> bool:
    """
    Return True if the IP address is in a private (RFC 1918) range.
    Also returns True for loopback and link-local addresses.
    """
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _make_flow_id(src_ip, src_port, dst_ip, dst_port, protocol) -> str:
    """
    Generate a stable flow ID for a packet.

    We sort the endpoints so that both directions of a conversation
    share the same flow ID.

    Example: TCP flow between 192.168.1.5:12345 and 8.8.8.8:443
             → "TCP-192.168.1.5:12345-8.8.8.8:443"   (if src < dst)
    """
    if src_ip is None or dst_ip is None:
        return "UNKNOWN"

    ep1 = f"{src_ip}:{src_port or 0}"
    ep2 = f"{dst_ip}:{dst_port or 0}"

    # Sort so both directions map to the same ID
    if ep1 > ep2:
        ep1, ep2 = ep2, ep1

    return f"{protocol}-{ep1}-{ep2}"


def _parse_dns_query(packet) -> str | None:
    """Extract the DNS question (query name) from a DNS packet."""
    try:
        if DNSQR in packet:
            return packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
    except Exception:
        pass
    return None


def _parse_dns_response(packet) -> str | None:
    """Extract the first DNS answer from a DNS response packet."""
    try:
        if DNS in packet and packet[DNS].ancount > 0:
            if DNSRR in packet:
                rdata = packet[DNSRR].rdata
                if isinstance(rdata, bytes):
                    return rdata.decode("utf-8", errors="replace")
                return str(rdata)
    except Exception:
        pass
    return None
