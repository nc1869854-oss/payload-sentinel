"""
capture/filters.py

Translate analyst-friendly filter text into BPF (Berkeley Packet Filter) strings.

BPF is the low-level filter language that Scapy and tcpdump understand.
Analysts should be able to type simple things like "80" or "192.168.1.10"
without learning BPF syntax.
"""


def translate_filter(user_input: str) -> str:
    """
    Convert a user-typed filter string into a BPF expression.

    Handles common shorthand inputs:

        "TCP"          → "tcp"
        "UDP"          → "udp"
        "ICMP"         → "icmp"
        "DNS"          → "udp port 53"
        "HTTP"         → "tcp port 80"
        "HTTPS"        → "tcp port 443"
        "80"           → "port 80"
        "443"          → "port 443"
        "192.168.1.10" → "host 192.168.1.10"
        "src 10.0.0.1" → "src host 10.0.0.1"
        "dst 10.0.0.1" → "dst host 10.0.0.1"
        ""             → ""  (capture everything)

    For anything that doesn't match a shorthand, we pass it through
    unchanged and let Scapy/libpcap validate it.
    """
    text = user_input.strip()

    if not text:
        return ""   # no filter — capture everything

    upper = text.upper()

    # Protocol shorthands
    protocol_map = {
        "TCP":   "tcp",
        "UDP":   "udp",
        "ICMP":  "icmp",
        "ARP":   "arp",
        "DNS":   "udp port 53",
        "HTTP":  "tcp port 80",
        "HTTPS": "tcp port 443",
        "TLS":   "tcp port 443",
        "SSH":   "tcp port 22",
        "FTP":   "tcp port 21",
        "SMTP":  "tcp port 25",
        "RDP":   "tcp port 3389",
    }

    if upper in protocol_map:
        return protocol_map[upper]

    # Pure port number (e.g. "443", "8080")
    if text.isdigit():
        return f"port {text}"

    # IP address  (e.g. "192.168.1.10" or "2001:db8::1")
    if _looks_like_ip(text):
        return f"host {text}"

    # "src <IP>" shorthand
    parts = text.split()
    if len(parts) == 2 and parts[0].lower() == "src" and _looks_like_ip(parts[1]):
        return f"src host {parts[1]}"

    # "dst <IP>" shorthand
    if len(parts) == 2 and parts[0].lower() == "dst" and _looks_like_ip(parts[1]):
        return f"dst host {parts[1]}"

    # Pass through as raw BPF — the user knows what they're doing
    return text


def _looks_like_ip(text: str) -> bool:
    """Return True if the string looks like an IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# Suggested filter strings shown in the UI as examples
FILTER_SUGGESTIONS = [
    "",
    "TCP",
    "UDP",
    "ICMP",
    "DNS",
    "HTTP",
    "HTTPS",
    "port 443",
    "port 80",
    "port 53",
]
