"""
investigation/local_intel.py

Offline network intelligence — no internet, no API keys, no downloads.

Everything here is answered from tables bundled inside the application:

  • service_for_port()     — well-known port → service name and risk note
  • classify_block()       — IANA special-purpose address blocks
  • organisation_hint()    — owner hint for well-known public ranges
  • describe_ip()          — one combined summary for the IP inspector

The organisation table covers widely published, stable ranges belonging to
large public services. It is a hint for triage, not an authoritative WHOIS
result, and the returned dict always says so.
"""

from __future__ import annotations

import ipaddress

# ─── Well-known ports ─────────────────────────────────────────────────────────
# port: (service, encrypted?, note)

PORTS: dict[int, tuple[str, bool, str]] = {
    20:    ("FTP data", False, "Credentials and files travel in the clear."),
    21:    ("FTP control", False, "Credentials travel in the clear."),
    22:    ("SSH", True, "Encrypted remote shell."),
    23:    ("Telnet", False, "Obsolete; everything is readable in transit."),
    25:    ("SMTP", False, "Mail transfer; often unencrypted."),
    53:    ("DNS", False, "Name lookups; commonly abused for tunnelling."),
    67:    ("DHCP server", False, "Address assignment."),
    68:    ("DHCP client", False, "Address assignment."),
    69:    ("TFTP", False, "No authentication at all."),
    80:    ("HTTP", False, "Web traffic in the clear."),
    110:   ("POP3", False, "Mail retrieval; credentials in the clear."),
    123:   ("NTP", False, "Time sync; used for amplification attacks."),
    135:   ("MS RPC", False, "Windows service mapper; should not face internet."),
    137:   ("NetBIOS name", False, "Legacy Windows naming."),
    138:   ("NetBIOS datagram", False, "Legacy Windows naming."),
    139:   ("NetBIOS session", False, "Legacy file sharing."),
    143:   ("IMAP", False, "Mail access; credentials in the clear."),
    161:   ("SNMP", False, "Device management; default community strings leak data."),
    389:   ("LDAP", False, "Directory queries in the clear."),
    443:   ("HTTPS", True, "Encrypted web traffic."),
    445:   ("SMB", False, "File sharing; a primary ransomware path."),
    465:   ("SMTPS", True, "Encrypted mail submission."),
    500:   ("IKE / IPsec", True, "VPN negotiation."),
    514:   ("Syslog", False, "Log shipping in the clear."),
    587:   ("SMTP submission", False, "Usually upgraded to TLS."),
    636:   ("LDAPS", True, "Encrypted directory queries."),
    993:   ("IMAPS", True, "Encrypted mail access."),
    995:   ("POP3S", True, "Encrypted mail retrieval."),
    1080:  ("SOCKS proxy", False, "Often used to tunnel around monitoring."),
    1194:  ("OpenVPN", True, "VPN tunnel."),
    1433:  ("MS SQL Server", False, "Database; must never face the internet."),
    1521:  ("Oracle DB", False, "Database; must never face the internet."),
    1723:  ("PPTP", False, "Obsolete VPN with broken encryption."),
    2049:  ("NFS", False, "File sharing with weak access control."),
    3128:  ("Squid proxy", False, "Web proxy."),
    3306:  ("MySQL", False, "Database; must never face the internet."),
    3389:  ("RDP", True, "Remote desktop; heavily brute-forced."),
    4444:  ("Metasploit default", False, "Common attack-tool listener port."),
    5060:  ("SIP", False, "Voice signalling."),
    5432:  ("PostgreSQL", False, "Database; must never face the internet."),
    5555:  ("ADB / misc", False, "Android debug bridge and various backdoors."),
    5900:  ("VNC", False, "Remote screen; frequently unauthenticated."),
    6379:  ("Redis", False, "Often unauthenticated by default."),
    6667:  ("IRC", False, "Historic botnet command channel."),
    8080:  ("HTTP alternate", False, "Web traffic in the clear."),
    8443:  ("HTTPS alternate", True, "Encrypted web traffic."),
    9001:  ("Tor ORPort", True, "Anonymity network relay."),
    9050:  ("Tor SOCKS", True, "Anonymity network client proxy."),
    9200:  ("Elasticsearch", False, "Often unauthenticated by default."),
    11211: ("Memcached", False, "Used for huge amplification attacks."),
    27017: ("MongoDB", False, "Often unauthenticated by default."),
    31337: ("Back Orifice", False, "Classic backdoor port."),
}

HIGH_RISK_PORTS = {23, 69, 135, 139, 445, 1433, 1521, 3306, 4444, 5432,
                   5555, 5900, 6379, 6667, 9200, 11211, 27017, 31337}

ANONYMITY_PORTS = {1080, 9001, 9050}


def service_for_port(port: int | None) -> dict:
    """Describe a port using the bundled table."""
    if port is None:
        return {"port": None, "service": "—", "encrypted": None,
                "note": "", "risk": "NONE"}

    try:
        number = int(port)
    except (TypeError, ValueError):
        return {"port": port, "service": "Unknown", "encrypted": None,
                "note": "", "risk": "NONE"}

    entry = PORTS.get(number)
    if entry:
        service, encrypted, note = entry
    elif number >= 49152:
        service, encrypted, note = ("Ephemeral / client port", None,
                                    "Short-lived port chosen by the operating system.")
    elif number >= 1024:
        service, encrypted, note = ("Registered / unassigned", None,
                                    "No well-known service on this port.")
    else:
        service, encrypted, note = ("Unassigned system port", None,
                                    "Reserved range with no common service.")

    if number in HIGH_RISK_PORTS:
        risk = "HIGH"
    elif number in ANONYMITY_PORTS:
        risk = "MEDIUM"
    elif entry and encrypted is False:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"port": number, "service": service, "encrypted": encrypted,
            "note": note, "risk": risk}


# ─── Special-purpose address blocks (RFC 6890 and friends) ────────────────────

SPECIAL_BLOCKS: list[tuple[str, str, str]] = [
    ("0.0.0.0/8",          "This network",        "Unspecified source address."),
    ("10.0.0.0/8",         "Private network",     "RFC 1918 internal address."),
    ("100.64.0.0/10",      "Carrier NAT",         "Shared provider address space."),
    ("127.0.0.0/8",        "Loopback",            "Traffic never leaves the machine."),
    ("169.254.0.0/16",     "Link-local",          "Self-assigned; no DHCP answered."),
    ("172.16.0.0/12",      "Private network",     "RFC 1918 internal address."),
    ("192.0.0.0/24",       "IETF protocol block", "Reserved for protocol assignments."),
    ("192.0.2.0/24",       "Documentation",       "Reserved for examples, not real hosts."),
    ("192.88.99.0/24",     "6to4 relay (retired)", "Legacy IPv6 relay anycast."),
    ("192.168.0.0/16",     "Private network",     "RFC 1918 internal address."),
    ("198.18.0.0/15",      "Benchmark testing",   "Reserved for network device tests."),
    ("198.51.100.0/24",    "Documentation",       "Reserved for examples, not real hosts."),
    ("203.0.113.0/24",     "Documentation",       "Reserved for examples, not real hosts."),
    ("224.0.0.0/4",        "Multicast",           "One-to-many delivery, not a single host."),
    ("240.0.0.0/4",        "Reserved",            "Reserved for future use."),
    ("255.255.255.255/32", "Broadcast",           "Sent to every host on the segment."),
    ("::1/128",            "Loopback (IPv6)",     "Traffic never leaves the machine."),
    ("fc00::/7",           "Unique local (IPv6)", "Private IPv6 address."),
    ("fe80::/10",          "Link-local (IPv6)",   "Self-assigned IPv6 address."),
    ("ff00::/8",           "Multicast (IPv6)",    "One-to-many delivery."),
]


def classify_block(ip_str: str) -> dict | None:
    """Return the special-purpose block an address belongs to, if any."""
    try:
        address = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return None

    for cidr, label, note in SPECIAL_BLOCKS:
        try:
            network = ipaddress.ip_network(cidr)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return {"block": cidr, "label": label, "note": note}
    return None


# ─── Organisation hints for well-known public ranges ──────────────────────────
# Stable, publicly documented ranges only. Triage hint, never authoritative.

ORG_BLOCKS: list[tuple[str, str, str]] = [
    ("1.1.1.0/24",       "Cloudflare",  "Public DNS resolver"),
    ("8.8.4.0/24",       "Google",      "Public DNS resolver"),
    ("8.8.8.0/24",       "Google",      "Public DNS resolver"),
    ("9.9.9.0/24",       "Quad9",       "Public DNS resolver"),
    ("13.32.0.0/15",     "Amazon AWS",  "CloudFront edge network"),
    ("13.64.0.0/11",     "Microsoft",   "Azure cloud"),
    ("17.0.0.0/8",       "Apple",       "Apple services"),
    ("20.0.0.0/11",      "Microsoft",   "Azure cloud"),
    ("23.32.0.0/11",     "Akamai",      "Content delivery network"),
    ("31.13.24.0/21",    "Meta",        "Facebook / Instagram"),
    ("34.64.0.0/10",     "Google",      "Google Cloud"),
    ("35.190.0.0/15",    "Google",      "Google Cloud"),
    ("40.64.0.0/10",     "Microsoft",   "Azure cloud"),
    ("52.0.0.0/10",      "Amazon AWS",  "EC2 compute"),
    ("54.64.0.0/11",     "Amazon AWS",  "EC2 compute"),
    ("64.233.160.0/19",  "Google",      "Google services"),
    ("66.102.0.0/20",    "Google",      "Google services"),
    ("74.125.0.0/16",    "Google",      "Google services"),
    ("104.16.0.0/12",    "Cloudflare",  "Reverse proxy / CDN"),
    ("140.82.112.0/20",  "GitHub",      "Source hosting"),
    ("142.250.0.0/15",   "Google",      "Google services"),
    ("151.101.0.0/16",   "Fastly",      "Content delivery network"),
    ("157.240.0.0/16",   "Meta",        "Facebook / Instagram"),
    ("162.125.0.0/16",   "Dropbox",     "File sync"),
    ("172.217.0.0/16",   "Google",      "Google services"),
    ("185.199.108.0/22", "GitHub",      "GitHub Pages"),
    ("204.79.197.0/24",  "Microsoft",   "Bing search"),
    ("208.67.222.0/24",  "Cisco OpenDNS", "Public DNS resolver"),
]


def organisation_hint(ip_str: str) -> dict | None:
    """Best-effort offline owner hint for a public address."""
    try:
        address = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return None
    if address.is_private or address.is_loopback or address.is_multicast:
        return None

    for cidr, org, purpose in ORG_BLOCKS:
        try:
            network = ipaddress.ip_network(cidr)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return {
                "organisation": org,
                "purpose":      purpose,
                "block":        cidr,
                "source":       "Bundled offline range table",
                "authoritative": False,
            }
    return None


# ─── Combined summary ─────────────────────────────────────────────────────────

def describe_ip(ip_str: str) -> dict:
    """
    One offline description of an address for the IP inspector:
    scope, special-purpose block, owner hint and a short plain sentence.
    """
    result = {
        "ip":            ip_str,
        "valid":         False,
        "version":       None,
        "scope":         "Unknown",
        "block":         None,
        "organisation":  None,
        "summary":       "This address could not be read.",
    }

    try:
        address = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return result

    result["valid"] = True
    result["version"] = address.version

    if address.is_loopback:
        result["scope"] = "Loopback"
    elif address.is_private:
        result["scope"] = "Private"
    elif address.is_multicast:
        result["scope"] = "Multicast"
    elif address.is_link_local:
        result["scope"] = "Link-local"
    elif address.is_reserved or address.is_unspecified:
        result["scope"] = "Reserved"
    else:
        result["scope"] = "Public"

    result["block"] = classify_block(ip_str)
    result["organisation"] = organisation_hint(ip_str)

    parts = [f"{ip_str} is a {result['scope'].lower()} IPv{address.version} address."]
    if result["block"]:
        parts.append(result["block"]["note"])
    if result["organisation"]:
        org = result["organisation"]
        parts.append(
            f"The range {org['block']} is published as belonging to "
            f"{org['organisation']} ({org['purpose']}). This is an offline hint, "
            "not a verified ownership record."
        )
    elif result["scope"] == "Public":
        parts.append("No bundled owner information matches this address.")

    result["summary"] = " ".join(parts)
    return result
