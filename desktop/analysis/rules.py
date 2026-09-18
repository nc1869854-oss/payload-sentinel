"""
analysis/rules.py

Local rule engine for Payload Capture Suite.

This is a deterministic, offline system — no AI, no cloud lookups.
Rules are data structures that describe a condition to check and
how to explain the result to an analyst.

Design philosophy:
  • Rules generate FINDINGS, not verdicts.
  • A finding is an observation that warrants investigation.
  • High severity ≠ definitely malicious.
  • The analyst makes the final call.

Adding a new rule:
  1. Write a check function: check_X(packets, flows) → list[dict]
  2. Add it to RULES list at the bottom of this file.
  3. Each returned dict must contain the keys shown in _make_finding().
"""

from collections import defaultdict, Counter
import datetime

from config.logger import get_logger

log = get_logger(__name__)


# ─── Finding builder ──────────────────────────────────────────────────────────

def _make_finding(severity: str, title: str, description: str,
                  evidence: list[str], recommendation: str,
                  related_ip: str = None, related_flow: str = None) -> dict:
    """
    Build a standardised finding dict.

    severity       : INFO | LOW | MEDIUM | HIGH | CRITICAL
    title          : short headline (shown in the alert table)
    description    : one paragraph explaining what was observed
    evidence       : list of bullet-point facts supporting the finding
    recommendation : what the analyst should do next
    related_ip     : IP address most associated with this finding
    related_flow   : flow_id most associated with this finding
    """
    return {
        "severity":       severity,
        "title":          title,
        "description":    description,
        "evidence":       evidence,           # list[str]
        "recommendation": recommendation,
        "related_ip":     related_ip,
        "related_flow":   related_flow,
        "created_at":     datetime.datetime.now().isoformat(timespec="seconds"),
    }


# ─── Individual rule check functions ─────────────────────────────────────────

def check_high_connection_frequency(packets: list[dict],
                                    flows: list[dict]) -> list[dict]:
    """
    Rule: A single source IP is responsible for an unusually large
    number of distinct flows in a short time window.

    Rationale: Legitimate traffic tends to maintain a small number of
    long-lived connections. Many short connections from one host
    could indicate scanning, C2 beaconing, or data exfiltration.
    """
    findings = []

    # Count how many distinct flows each source IP opened
    src_flow_counts: dict[str, set] = defaultdict(set)

    for flow in flows:
        src_ip = flow.get("src_ip")
        if src_ip:
            src_flow_counts[src_ip].add(flow["flow_id"])

    # Threshold: more than 50 distinct outbound flows is unusual
    THRESHOLD = 50

    for ip, flow_ids in src_flow_counts.items():
        count = len(flow_ids)
        if count >= THRESHOLD:
            findings.append(_make_finding(
                severity="MEDIUM",
                title="High Outbound Connection Frequency",
                description=(
                    f"Source IP {ip} initiated {count} distinct network flows "
                    f"during this capture session. A high number of outbound "
                    f"connections from a single host can indicate port scanning, "
                    f"automated beaconing, or data-gathering behaviour. This "
                    f"observation requires investigation to determine context."
                ),
                evidence=[
                    f"Source IP: {ip}",
                    f"Distinct flows opened: {count}",
                    f"Threshold for this rule: {THRESHOLD}",
                ],
                recommendation=(
                    "Open Flow Investigation and filter by this IP. "
                    "Check whether connections are to many different destinations "
                    "(scanning) or the same destination repeatedly (beaconing). "
                    "Correlate with process activity on the host if possible."
                ),
                related_ip=ip,
            ))

    return findings


def check_many_unique_destinations(packets: list[dict],
                                   flows: list[dict]) -> list[dict]:
    """
    Rule: A source IP contacted an unusually large number of distinct
    destination IPs.

    Rationale: Contacting many unique hosts in a short period is a
    common characteristic of network scanning and lateral movement.
    """
    findings = []

    # Map source IP → set of unique destination IPs
    src_to_dsts: dict[str, set] = defaultdict(set)

    for flow in flows:
        src = flow.get("src_ip")
        dst = flow.get("dst_ip")
        if src and dst:
            src_to_dsts[src].add(dst)

    THRESHOLD = 20   # contacting 20+ unique IPs is unusual

    for src_ip, dsts in src_to_dsts.items():
        if len(dsts) >= THRESHOLD:
            sample = sorted(dsts)[:5]   # show a few examples
            findings.append(_make_finding(
                severity="MEDIUM",
                title="Contact with Many Unique Destinations",
                description=(
                    f"Host {src_ip} contacted {len(dsts)} distinct destination "
                    f"IP addresses during this session. Legitimate hosts typically "
                    f"communicate with a small number of servers. This pattern "
                    f"may indicate network scanning or automated enumeration."
                ),
                evidence=[
                    f"Source IP: {src_ip}",
                    f"Unique destinations contacted: {len(dsts)}",
                    f"Sample destinations: {', '.join(sample)}",
                    f"Threshold: {THRESHOLD}",
                ],
                recommendation=(
                    "Review the destination IPs in IP Investigation. "
                    "Determine whether these are legitimate service endpoints "
                    "or unfamiliar addresses. Check for sequential IP patterns "
                    "which could indicate a subnet scan."
                ),
                related_ip=src_ip,
            ))

    return findings


def check_large_payload(packets: list[dict], flows: list[dict]) -> list[dict]:
    """
    Rule: A packet carries an unusually large payload.

    Rationale: Very large single payloads can indicate bulk data transfer,
    file exfiltration, or exploit payloads. Context determines significance.
    """
    findings = []

    # Look for payloads larger than 8 KB in a single packet
    THRESHOLD_BYTES = 8192

    large_packets = [
        p for p in packets
        if p.get("payload_size", 0) >= THRESHOLD_BYTES
    ]

    if large_packets:
        largest = max(large_packets, key=lambda p: p["payload_size"])
        findings.append(_make_finding(
            severity="LOW",
            title="Unusually Large Packet Payload",
            description=(
                f"{len(large_packets)} packet(s) carried a payload exceeding "
                f"{THRESHOLD_BYTES:,} bytes. The largest was "
                f"{largest['payload_size']:,} bytes "
                f"(packet #{largest['packet_number']}). Large payloads are common "
                f"for file transfers and streaming but may warrant review in "
                f"unexpected contexts."
            ),
            evidence=[
                f"Packets exceeding {THRESHOLD_BYTES:,} bytes: {len(large_packets)}",
                f"Largest payload: {largest['payload_size']:,} bytes "
                f"(packet #{largest['packet_number']})",
                f"Protocol: {largest.get('protocol', 'Unknown')}",
                f"Destination: {largest.get('dst_ip')}:{largest.get('dst_port')}",
            ],
            recommendation=(
                "Select the large packet in the Capture window and inspect "
                "the ASCII payload tab. Determine whether the content is "
                "expected (software update, media stream, backup) or unusual."
            ),
            related_ip=largest.get("dst_ip"),
            related_flow=largest.get("flow_id"),
        ))

    return findings


def check_dns_query_volume(packets: list[dict], flows: list[dict]) -> list[dict]:
    """
    Rule: An unusually high number of DNS queries from a single host.

    Rationale: Normal hosts make occasional DNS lookups. Hundreds of
    DNS queries per session from one host could indicate:
    - DNS tunnelling (data exfiltration over DNS)
    - C2 using DNS for command delivery
    - Malware performing domain generation algorithm (DGA) lookups
    """
    findings = []

    # Count DNS packets per source IP
    dns_counts: Counter = Counter(
        p["src_ip"]
        for p in packets
        if p.get("is_dns") and p.get("src_ip")
    )

    THRESHOLD = 100

    for src_ip, count in dns_counts.items():
        if count >= THRESHOLD:
            # Collect unique domains queried by this IP
            domains = list({
                p.get("dns_query") for p in packets
                if p.get("is_dns") and p.get("src_ip") == src_ip
                and p.get("dns_query")
            })[:10]

            findings.append(_make_finding(
                severity="MEDIUM",
                title="High DNS Query Volume",
                description=(
                    f"Host {src_ip} generated {count} DNS queries during this "
                    f"session. While some applications are DNS-heavy, this volume "
                    f"may indicate DNS tunnelling, DGA-based malware checking for "
                    f"available C2 domains, or another automated DNS-intensive "
                    f"process."
                ),
                evidence=[
                    f"Source IP: {src_ip}",
                    f"DNS packets: {count}",
                    f"Sample domains: {', '.join(domains) if domains else 'not extracted'}",
                    f"Threshold: {THRESHOLD}",
                ],
                recommendation=(
                    "Open the Timeline and filter by DNS to see the sequence of "
                    "queries. Look for random-looking domain names (DGA indicator) "
                    "or high data volumes in DNS response packets (tunnelling). "
                    "Compare domains against expected application behaviour."
                ),
                related_ip=src_ip,
            ))

    return findings


def check_unencrypted_sensitive_ports(packets: list[dict],
                                      flows: list[dict]) -> list[dict]:
    """
    Rule: Traffic observed on ports typically used for sensitive unencrypted
    protocols (Telnet, FTP, plain HTTP on internal traffic).

    Rationale: These protocols transmit credentials and data in plaintext.
    Their presence on a monitored network is worth noting.
    """
    findings = []

    sensitive_ports = {
        21:  ("FTP", "File Transfer Protocol — transmits credentials in plaintext"),
        23:  ("Telnet", "Telnet — transmits all data including credentials in plaintext"),
        110: ("POP3", "POP3 — email retrieval without encryption"),
        143: ("IMAP", "IMAP — email access without encryption"),
    }

    for port, (name, description) in sensitive_ports.items():
        matching_flows = [
            f for f in flows
            if f.get("dst_port") == port or f.get("src_port") == port
        ]

        if matching_flows:
            flow = matching_flows[0]
            findings.append(_make_finding(
                severity="LOW",
                title=f"Unencrypted Protocol Detected: {name}",
                description=(
                    f"Traffic was observed on port {port} ({name}). "
                    f"{description}. "
                    f"If this traffic is expected, ensure it is confined to "
                    f"isolated segments. Otherwise, consider whether the service "
                    f"should be replaced with an encrypted alternative."
                ),
                evidence=[
                    f"Protocol: {name} (port {port})",
                    f"Flows involving this port: {len(matching_flows)}",
                    f"Example endpoint: {flow.get('src_ip')} → {flow.get('dst_ip')}",
                ],
                recommendation=(
                    f"Review the flows involving port {port}. If this service "
                    f"is intentional, document it. If unexpected, investigate "
                    f"which host initiated the connection and why."
                ),
                related_ip=flow.get("src_ip"),
                related_flow=flow.get("flow_id"),
            ))

    return findings


def check_protocol_port_mismatch(packets: list[dict],
                                 flows: list[dict]) -> list[dict]:
    """
    Rule: Traffic on a well-known port does not match the expected protocol.

    Rationale: Malware and tunnelling tools sometimes use common ports (80, 443)
    to blend in, but the actual protocol carried differs from what's expected.
    This is hard to detect without DPI, but payload analysis can give clues.

    We look for flows where:
    - Port 443 is used but the flow appears to be plain TCP (no TLS negotiation
      observable from Scapy headers alone — a rough heuristic)
    """
    # NOTE: Without deep packet inspection we can only flag potential mismatches.
    # This rule looks for non-TLS flows on port 443 with payload_size > 0.
    findings = []

    # Port 443 is a TCP port; anything else there is a protocol mismatch.
    wrong_proto_443 = [
        f for f in flows
        if (f.get("dst_port") == 443 or f.get("src_port") == 443)
        and f.get("protocol") not in ("TCP", "TLS", "UNKNOWN", None)
    ]

    if wrong_proto_443:
        findings.append(_make_finding(
            severity="MEDIUM",
            title="Unexpected protocol on the HTTPS port",
            description=(
                f"{len(wrong_proto_443)} conversations used port 443 with a "
                "protocol other than TCP. Secure web traffic is always TCP, so "
                "something else is being carried over a port that firewalls "
                "usually leave open."
            ),
            evidence=[
                f"Conversations affected: {len(wrong_proto_443)}",
                "Protocols seen: " + ", ".join(sorted({
                    str(f.get("protocol")) for f in wrong_proto_443
                })),
            ],
            recommendation=(
                "Inspect these conversations. Non-TCP traffic on port 443 is a "
                "known way to tunnel data past simple firewall rules."
            ),
            related_ip=wrong_proto_443[0].get("dst_ip"),
        ))

    # More useful: flag flows on 443 that transferred very little data
    # (could be failed TLS or non-TLS traffic)
    small_443_flows = [
        f for f in flows
        if (f.get("dst_port") == 443)
        and f.get("byte_count", 0) < 100
        and f.get("packet_count", 0) >= 3
    ]

    if small_443_flows:
        findings.append(_make_finding(
            severity="LOW",
            title="Minimal-Data Flows on HTTPS Port",
            description=(
                f"{len(small_443_flows)} flow(s) used port 443 (HTTPS) but "
                f"transferred fewer than 100 bytes despite multiple packets. "
                f"This can indicate failed TLS handshakes, port probing, or "
                f"traffic that does not conform to HTTPS."
            ),
            evidence=[
                f"Flows on port 443 with <100 bytes: {len(small_443_flows)}",
                f"Example: {small_443_flows[0].get('src_ip')} → "
                f"{small_443_flows[0].get('dst_ip')}",
            ],
            recommendation=(
                "Inspect these flows in Flow Investigation. Check whether "
                "TLS handshakes completed. Very small byte counts on HTTPS "
                "flows may indicate probing or connection failures worth investigating."
            ),
            related_ip=small_443_flows[0].get("dst_ip"),
        ))

    return findings


def check_repeated_connection_failures(packets: list[dict],
                                       flows: list[dict]) -> list[dict]:
    """
    Rule: Many flows to the same destination that transferred very little data.

    Rationale: Rapid connection-teardown cycles can indicate:
    - Port scanning (SYN without completing handshake)
    - Repeated failed authentication
    - C2 check-in failures
    """
    findings = []

    # Group flows by destination IP
    dst_tiny_flows: dict[str, list] = defaultdict(list)

    for flow in flows:
        dst_ip = flow.get("dst_ip")
        # A flow is "tiny" if it has few packets and very little data
        if dst_ip and flow.get("packet_count", 0) <= 3 and flow.get("byte_count", 0) < 200:
            dst_tiny_flows[dst_ip].append(flow)

    THRESHOLD = 10   # 10+ tiny flows to the same dest is unusual

    for dst_ip, tiny in dst_tiny_flows.items():
        if len(tiny) >= THRESHOLD:
            findings.append(_make_finding(
                severity="MEDIUM",
                title="Repeated Short-Duration Flows to Single Destination",
                description=(
                    f"{len(tiny)} very short flows were observed to {dst_ip}. "
                    f"Each transferred fewer than 200 bytes and involved at most "
                    f"3 packets. This pattern is consistent with repeated "
                    f"connection attempts that did not complete, which can indicate "
                    f"scanning, failed handshakes, or automated probing."
                ),
                evidence=[
                    f"Destination IP: {dst_ip}",
                    f"Short flows (≤3 pkts, <200 B): {len(tiny)}",
                    f"Ports targeted: {', '.join(str(f.get('dst_port','?')) for f in tiny[:5])}",
                ],
                recommendation=(
                    "Investigate whether this destination is a known service. "
                    "If it is an internal IP, check the host for signs of "
                    "network enumeration. If external, investigate the initiating host."
                ),
                related_ip=dst_ip,
            ))

    return findings


def check_icmp_flood(packets: list[dict], flows: list[dict]) -> list[dict]:
    """
    Rule: A large number of ICMP packets from a single source.

    Rationale: Large volumes of ICMP can indicate ping flooding,
    ICMP-based network reconnaissance, or misconfigured monitoring tools.
    """
    findings = []

    icmp_by_src: Counter = Counter(
        p["src_ip"]
        for p in packets
        if p.get("protocol") == "ICMP" and p.get("src_ip")
    )

    THRESHOLD = 50

    for src_ip, count in icmp_by_src.items():
        if count >= THRESHOLD:
            findings.append(_make_finding(
                severity="LOW",
                title="High ICMP Packet Volume",
                description=(
                    f"Host {src_ip} sent {count} ICMP packets during this "
                    f"session. While ICMP is commonly used for ping and "
                    f"traceroute, high volumes from a single host may indicate "
                    f"a network sweep or misconfigured monitoring."
                ),
                evidence=[
                    f"Source IP: {src_ip}",
                    f"ICMP packets: {count}",
                    f"Threshold: {THRESHOLD}",
                ],
                recommendation=(
                    "Check whether ICMP is expected from this host. "
                    "Review destination IPs to determine if this is a "
                    "targeted ping or a broad sweep."
                ),
                related_ip=src_ip,
            ))

    return findings


def check_non_standard_ports(packets: list[dict], flows: list[dict]) -> list[dict]:
    """
    Rule: TCP or UDP traffic observed on unusual high-numbered ports
    that are not commonly associated with known services.

    Rationale: C2 frameworks often use high ephemeral ports to avoid
    detection by simple port-based filters. This is low-severity because
    high ports are also used legitimately by many applications.
    """
    findings = []

    # Ports below this are considered "standard" for this rule
    WELL_KNOWN_LIMIT = 1024

    # Known legitimate high ports to ignore
    COMMON_HIGH_PORTS = {
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
        8443, 8888, 9000, 9200, 27017,
    }

    unusual_dst_flows = [
        f for f in flows
        if (f.get("dst_port") or 0) > WELL_KNOWN_LIMIT
        and f.get("dst_port") not in COMMON_HIGH_PORTS
        and f.get("byte_count", 0) > 5000   # only flag if significant data moved
    ]

    if len(unusual_dst_flows) >= 3:
        # Report the top offenders by data volume
        top = sorted(unusual_dst_flows,
                     key=lambda f: f.get("byte_count", 0), reverse=True)[:5]
        findings.append(_make_finding(
            severity="INFO",
            title="Significant Traffic on Non-Standard High Ports",
            description=(
                f"{len(unusual_dst_flows)} flow(s) carried significant data "
                f"(>5 KB) to destination ports above 1024 that are not commonly "
                f"associated with well-known services. This is informational — "
                f"many legitimate applications use high ports. Review if unexpected."
            ),
            evidence=[
                f"Flows on unusual high ports: {len(unusual_dst_flows)}",
            ] + [
                f"Port {f['dst_port']}: {f['src_ip']} → {f['dst_ip']} "
                f"({f['byte_count']:,} B)"
                for f in top
            ],
            recommendation=(
                "Identify the application responsible for each of these flows. "
                "If the process is unknown, investigate further."
            ),
        ))

    return findings


# ─── Rule registry ────────────────────────────────────────────────────────────

# All active rules in priority order.
# Each entry is a callable: (packets, flows) → list[finding dict]
RULES: list = [
    check_high_connection_frequency,
    check_many_unique_destinations,
    check_large_payload,
    check_dns_query_volume,
    check_unencrypted_sensitive_ports,
    check_protocol_port_mismatch,
    check_repeated_connection_failures,
    check_icmp_flood,
    check_non_standard_ports,
]

# Advanced behaviour-based rules (beaconing, scanning, exfiltration, entropy,
# DNS tunnelling, off-hours activity) live in analysis/advanced_rules.py and are
# appended here so run_all_rules() covers everything.
try:
    from analysis.advanced_rules import ADVANCED_RULES, score_findings  # noqa: F401
    RULES.extend(ADVANCED_RULES)
except Exception as _exc:                                 # pragma: no cover
    print(f"[Rules] Advanced rules unavailable: {_exc}")


# ─── Rule runner ──────────────────────────────────────────────────────────────

def run_all_rules(packets: list[dict], flows: list[dict]) -> list[dict]:
    """
    Execute every rule and return a combined list of findings.

    Rules that raise exceptions are skipped with a warning so one
    broken rule cannot prevent the others from running.
    """
    all_findings: list[dict] = []

    for rule_func in RULES:
        try:
            results = rule_func(packets, flows)
            all_findings.extend(results)
        except Exception as e:
            # Log but continue — a broken rule must not crash the application
            log.warning("Rule %s raised an error: %s", rule_func.__name__, e)

    return all_findings


def severity_sort_key(finding: dict) -> int:
    """
    Return a numeric sort key so findings can be sorted highest-first.
    CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3, INFO=4
    """
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(finding.get("severity", "INFO"), 4)
