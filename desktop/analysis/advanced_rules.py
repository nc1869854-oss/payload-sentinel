"""
analysis/advanced_rules.py

Advanced, fully offline detection rules for Payload Capture Suite.

These complement analysis/rules.py with behaviour-based detections that
need no internet access and no API keys:

  • Beaconing        — regular, machine-like call-home intervals
  • Port scanning    — one source touching many ports on one host
  • Host sweeping    — one source touching the same port on many hosts
  • Data exfil       — large outbound volume to a single external host
  • Entropy anomaly  — high-entropy payloads on plaintext ports
  • DNS tunnelling   — long / high-entropy DNS query names
  • Off-hours        — sustained activity outside normal working hours
  • Beacon-like DNS  — repeated identical queries at fixed intervals

Every rule returns a list of finding dicts in the same shape used by
analysis/rules.py, plus two extra keys:

  technique   — MITRE-ATT&CK-style technique label (informational)
  confidence  — 0..100 integer

Each rule is defensive: bad or missing fields never raise.
"""

from __future__ import annotations

import datetime
import math
import statistics
from collections import defaultdict, Counter

from config.logger import get_logger

log = get_logger(__name__)


# ─── Tunables ─────────────────────────────────────────────────────────────────

BEACON_MIN_EVENTS        = 6      # connections needed before timing is judged
BEACON_MAX_JITTER_RATIO  = 0.22   # stddev / mean below this looks automated
PORT_SCAN_MIN_PORTS      = 15     # distinct ports on one host
HOST_SWEEP_MIN_HOSTS     = 20     # distinct hosts on one port
EXFIL_MIN_BYTES          = 5_000_000
EXFIL_MIN_RATIO          = 4.0    # outbound / inbound
ENTROPY_HIGH             = 7.2    # bits per byte (max is 8.0)
DNS_LONG_LABEL           = 45     # characters in a single DNS label
OFF_HOURS_START          = 22     # 22:00
OFF_HOURS_END            = 6      # 06:00
OFF_HOURS_MIN_PACKETS    = 200

PLAINTEXT_PORTS = {21, 23, 25, 80, 110, 143, 389, 1433, 3306, 5432, 8080}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _finding(severity: str, title: str, description: str,
             evidence: list[str], recommendation: str,
             technique: str = "", confidence: int = 60,
             related_ip: str | None = None,
             related_flow: str | None = None) -> dict:
    """Build a finding dict compatible with analysis/rules.py."""
    return {
        "severity":       severity,
        "title":          title,
        "description":    description,
        "evidence":       list(evidence),
        "recommendation": recommendation,
        "related_ip":     related_ip,
        "related_flow":   related_flow,
        "technique":      technique,
        "confidence":     max(0, min(100, int(confidence))),
        "created_at":     datetime.datetime.now().isoformat(timespec="seconds"),
    }


def _parse_time(value) -> datetime.datetime | None:
    """Parse an ISO timestamp string; return None when unusable."""
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        return value
    try:
        return datetime.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _is_external(direction: str) -> bool:
    return str(direction or "").upper() in ("OUTGOING", "INCOMING", "EXTERNAL")


def _intervals(times: list[datetime.datetime]) -> list[float]:
    """Seconds between consecutive sorted timestamps."""
    ordered = sorted(times)
    return [
        (ordered[i + 1] - ordered[i]).total_seconds()
        for i in range(len(ordered) - 1)
    ]


def _jitter_ratio(gaps: list[float]) -> float | None:
    """Coefficient of variation of the gaps; lower means more regular."""
    usable = [g for g in gaps if g > 0.05]
    if len(usable) < 3:
        return None
    mean = statistics.fmean(usable)
    if mean <= 0:
        return None
    return statistics.pstdev(usable) / mean


def _entropy(text: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _fmt_bytes(num: int) -> str:
    step = 1024.0
    value = float(num or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < step:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= step
    return f"{value:.1f} TB"


# ─── Rule: beaconing ──────────────────────────────────────────────────────────

def check_beaconing(packets: list[dict], flows: list[dict]) -> list[dict]:
    """
    Detect call-home beaconing: a local host contacting the same external
    endpoint at highly regular intervals. Human traffic is irregular;
    automated beacons are not.
    """
    findings: list[dict] = []
    by_pair: dict[tuple, list[datetime.datetime]] = defaultdict(list)

    for pkt in packets:
        if not _is_external(pkt.get("direction")):
            continue
        src, dst = pkt.get("src_ip"), pkt.get("dst_ip")
        stamp = _parse_time(pkt.get("capture_time"))
        if not (src and dst and stamp):
            continue
        by_pair[(src, dst, pkt.get("dst_port"))].append(stamp)

    for (src, dst, port), times in by_pair.items():
        if len(times) < BEACON_MIN_EVENTS:
            continue
        gaps = _intervals(times)
        jitter = _jitter_ratio(gaps)
        if jitter is None or jitter > BEACON_MAX_JITTER_RATIO:
            continue

        mean_gap = statistics.fmean([g for g in gaps if g > 0.05])
        confidence = int(max(40, min(96, (1 - jitter) * 100)))
        severity = "HIGH" if jitter < 0.1 else "MEDIUM"

        findings.append(_finding(
            severity=severity,
            title=f"Regular beaconing to {dst}",
            description=(
                f"{src} contacted {dst}:{port} {len(times)} times with a very "
                f"regular gap of about {mean_gap:.1f} seconds. Timing this "
                "consistent is typical of automated software checking in with "
                "a server rather than a person using an application."
            ),
            evidence=[
                f"Connections observed: {len(times)}",
                f"Average interval: {mean_gap:.2f} s",
                f"Timing jitter: {jitter * 100:.1f}% (lower is more automated)",
                f"Destination port: {port}",
            ],
            recommendation=(
                "Identify the process on the source host responsible for this "
                "traffic. If it is not a known updater or monitoring agent, "
                "isolate the host and block the destination."
            ),
            technique="T1071 — Application Layer Protocol (C2)",
            confidence=confidence,
            related_ip=dst,
        ))

    return findings


# ─── Rule: port scanning ──────────────────────────────────────────────────────

def check_port_scan(packets: list[dict], flows: list[dict]) -> list[dict]:
    """Detect one source probing many different ports on a single host."""
    findings: list[dict] = []
    ports_by_pair: dict[tuple, set] = defaultdict(set)

    for pkt in packets:
        src, dst, port = pkt.get("src_ip"), pkt.get("dst_ip"), pkt.get("dst_port")
        if src and dst and port:
            ports_by_pair[(src, dst)].add(port)

    for (src, dst), ports in ports_by_pair.items():
        if len(ports) < PORT_SCAN_MIN_PORTS:
            continue
        sample = ", ".join(str(p) for p in sorted(ports)[:12])
        findings.append(_finding(
            severity="HIGH" if len(ports) >= PORT_SCAN_MIN_PORTS * 3 else "MEDIUM",
            title=f"Port scan pattern from {src}",
            description=(
                f"{src} contacted {len(ports)} different ports on {dst}. "
                "Touching many ports on one machine in a single session is the "
                "signature of a port scan looking for exposed services."
            ),
            evidence=[
                f"Distinct ports contacted: {len(ports)}",
                f"Target host: {dst}",
                f"Sample of ports: {sample}",
            ],
            recommendation=(
                "Confirm whether an authorised vulnerability scan was running. "
                "If not, block the source and review what services responded."
            ),
            technique="T1046 — Network Service Discovery",
            confidence=80,
            related_ip=src,
        ))

    return findings


def check_host_sweep(packets: list[dict], flows: list[dict]) -> list[dict]:
    """Detect one source probing the same port across many hosts."""
    findings: list[dict] = []
    hosts_by_port: dict[tuple, set] = defaultdict(set)

    for pkt in packets:
        src, dst, port = pkt.get("src_ip"), pkt.get("dst_ip"), pkt.get("dst_port")
        if src and dst and port:
            hosts_by_port[(src, port)].add(dst)

    for (src, port), hosts in hosts_by_port.items():
        if len(hosts) < HOST_SWEEP_MIN_HOSTS:
            continue
        findings.append(_finding(
            severity="MEDIUM",
            title=f"Network sweep on port {port} from {src}",
            description=(
                f"{src} contacted port {port} on {len(hosts)} different hosts. "
                "Sweeping one port across a network is how an attacker finds "
                "every machine running a particular service."
            ),
            evidence=[
                f"Hosts contacted: {len(hosts)}",
                f"Port swept: {port}",
                f"Sample: {', '.join(sorted(hosts)[:8])}",
            ],
            recommendation=(
                "Verify the source is an approved scanner or asset-inventory "
                "tool. Otherwise treat it as reconnaissance and contain it."
            ),
            technique="T1018 — Remote System Discovery",
            confidence=75,
            related_ip=src,
        ))

    return findings


# ─── Rule: data exfiltration volume ───────────────────────────────────────────

def check_exfiltration_volume(packets: list[dict], flows: list[dict]) -> list[dict]:
    """Detect a large, heavily one-sided outbound transfer to one host."""
    findings: list[dict] = []
    out_bytes: dict[str, int] = defaultdict(int)
    in_bytes: dict[str, int] = defaultdict(int)

    for pkt in packets:
        size = int(pkt.get("packet_size") or 0)
        direction = str(pkt.get("direction") or "").upper()
        if direction == "OUTGOING" and pkt.get("dst_ip"):
            out_bytes[pkt["dst_ip"]] += size
        elif direction == "INCOMING" and pkt.get("src_ip"):
            in_bytes[pkt["src_ip"]] += size

    for host, sent in out_bytes.items():
        if sent < EXFIL_MIN_BYTES:
            continue
        received = in_bytes.get(host, 0)
        ratio = sent / received if received else float("inf")
        if ratio < EXFIL_MIN_RATIO:
            continue
        findings.append(_finding(
            severity="CRITICAL" if sent > EXFIL_MIN_BYTES * 10 else "HIGH",
            title=f"Large one-way upload to {host}",
            description=(
                f"This machine sent {_fmt_bytes(sent)} to {host} while "
                f"receiving only {_fmt_bytes(received)}. Normal browsing "
                "downloads far more than it uploads, so a heavily one-sided "
                "transfer can mean data is leaving the network."
            ),
            evidence=[
                f"Bytes sent: {_fmt_bytes(sent)}",
                f"Bytes received: {_fmt_bytes(received)}",
                f"Send/receive ratio: "
                f"{'unbounded' if received == 0 else f'{ratio:.1f}x'}",
            ],
            recommendation=(
                "Identify the uploading process and the data involved. If the "
                "destination is not an approved backup or sync service, block "
                "it and preserve this session as evidence."
            ),
            technique="T1041 — Exfiltration Over C2 Channel",
            confidence=78,
            related_ip=host,
        ))

    return findings


# ─── Rule: entropy anomaly ────────────────────────────────────────────────────

def check_entropy_anomaly(packets: list[dict], flows: list[dict]) -> list[dict]:
    """
    Detect encrypted or compressed payloads travelling over ports that are
    normally plaintext — a common way to hide data inside ordinary traffic.
    """
    findings: list[dict] = []
    suspect: dict[tuple, list[float]] = defaultdict(list)

    for pkt in packets:
        port = pkt.get("dst_port")
        entropy = pkt.get("payload_entropy")
        if port not in PLAINTEXT_PORTS or entropy is None:
            continue
        try:
            value = float(entropy)
        except (TypeError, ValueError):
            continue
        if value >= ENTROPY_HIGH and int(pkt.get("payload_size") or 0) >= 64:
            suspect[(pkt.get("dst_ip"), port)].append(value)

    for (host, port), values in suspect.items():
        if len(values) < 3:
            continue
        avg = statistics.fmean(values)
        findings.append(_finding(
            severity="MEDIUM",
            title=f"Scrambled data on plaintext port {port}",
            description=(
                f"{len(values)} packets sent to {host}:{port} carried data that "
                f"looks encrypted or compressed (randomness {avg:.2f} of 8.0). "
                "This port normally carries readable text, so hidden content "
                "may be tunnelled through it."
            ),
            evidence=[
                f"Packets affected: {len(values)}",
                f"Average randomness: {avg:.2f} / 8.00",
                f"Destination: {host}:{port}",
            ],
            recommendation=(
                "Inspect the payloads in the packet view. Tunnelling encrypted "
                "content over a plaintext port usually bypasses monitoring."
            ),
            technique="T1573 — Encrypted Channel",
            confidence=65,
            related_ip=host,
        ))

    return findings


# ─── Rule: DNS tunnelling ─────────────────────────────────────────────────────

def check_dns_tunnelling(packets: list[dict], flows: list[dict]) -> list[dict]:
    """Detect DNS queries that look like a data channel rather than lookups."""
    findings: list[dict] = []
    suspicious: dict[str, list[str]] = defaultdict(list)

    for pkt in packets:
        query = pkt.get("dns_query")
        if not query:
            continue
        labels = str(query).split(".")
        longest = max((len(part) for part in labels), default=0)
        first = labels[0] if labels else ""
        if longest >= DNS_LONG_LABEL or (_entropy(first) > 3.6 and len(first) > 20):
            domain = ".".join(labels[-2:]) if len(labels) >= 2 else str(query)
            suspicious[domain].append(str(query))

    for domain, queries in suspicious.items():
        if len(queries) < 3:
            continue
        findings.append(_finding(
            severity="HIGH",
            title=f"Possible DNS tunnelling via {domain}",
            description=(
                f"{len(queries)} lookups under {domain} used unusually long, "
                "random-looking names. DNS is often abused as a covert channel "
                "because it is rarely blocked."
            ),
            evidence=[
                f"Suspicious queries: {len(queries)}",
                f"Longest label: {max(len(p) for q in queries for p in q.split('.'))} characters",
                f"Example: {queries[0][:90]}",
            ],
            recommendation=(
                "Block the parent domain at your resolver and inspect the host "
                "making the lookups for unauthorised software."
            ),
            technique="T1071.004 — DNS",
            confidence=72,
        ))

    return findings


# ─── Rule: off-hours activity ─────────────────────────────────────────────────

def check_off_hours_activity(packets: list[dict], flows: list[dict]) -> list[dict]:
    """Flag sustained external traffic late at night."""
    night = 0
    hosts: Counter = Counter()

    for pkt in packets:
        stamp = _parse_time(pkt.get("capture_time"))
        if not stamp or not _is_external(pkt.get("direction")):
            continue
        hour = stamp.hour
        if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
            night += 1
            if pkt.get("dst_ip"):
                hosts[pkt["dst_ip"]] += 1

    if night < OFF_HOURS_MIN_PACKETS:
        return []

    top = ", ".join(f"{ip} ({count})" for ip, count in hosts.most_common(5))
    return [_finding(
        severity="LOW",
        title="Sustained activity outside working hours",
        description=(
            f"{night} external packets were sent or received between "
            f"{OFF_HOURS_START}:00 and {OFF_HOURS_END:02d}:00. Automated or "
            "unattended software is more likely to be active at these times "
            "than a person."
        ),
        evidence=[
            f"Off-hours external packets: {night}",
            f"Most contacted hosts: {top or 'n/a'}",
        ],
        recommendation=(
            "Cross-check against scheduled backups and updates. Unexplained "
            "night activity deserves a closer look at the top hosts listed."
        ),
        technique="T1029 — Scheduled Transfer",
        confidence=50,
    )]


# ─── Registry ─────────────────────────────────────────────────────────────────

ADVANCED_RULES: list = [
    check_beaconing,
    check_port_scan,
    check_host_sweep,
    check_exfiltration_volume,
    check_entropy_anomaly,
    check_dns_tunnelling,
    check_off_hours_activity,
]


# ─── Risk scoring ─────────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH":     22,
    "MEDIUM":   10,
    "LOW":      4,
    "INFO":     1,
}


def score_findings(findings: list[dict]) -> dict:
    """
    Turn a list of findings into a single 0-100 session risk score with a
    plain-language band, so the dashboard can show one honest headline number.
    """
    raw = 0.0
    counts: Counter = Counter()

    for finding in findings or []:
        severity = str(finding.get("severity", "INFO")).upper()
        counts[severity] += 1
        weight = SEVERITY_WEIGHT.get(severity, 1)
        confidence = finding.get("confidence", 70)
        try:
            factor = max(0.2, min(1.0, float(confidence) / 100.0))
        except (TypeError, ValueError):
            factor = 0.7
        raw += weight * factor

    # Saturating curve: many findings raise the score but never past 100.
    score = int(round(100 * (1 - math.exp(-raw / 55.0))))

    if score >= 80:
        band = "CRITICAL"
    elif score >= 60:
        band = "HIGH"
    elif score >= 35:
        band = "MEDIUM"
    elif score > 0:
        band = "LOW"
    else:
        band = "CLEAN"

    return {
        "score":  score,
        "band":   band,
        "counts": dict(counts),
        "total":  sum(counts.values()),
    }


def run_advanced_rules(packets: list[dict], flows: list[dict]) -> list[dict]:
    """Run every advanced rule; a failing rule never stops the others."""
    results: list[dict] = []
    for rule in ADVANCED_RULES:
        try:
            results.extend(rule(packets or [], flows or []) or [])
        except Exception as exc:                      # noqa: BLE001
            log.warning("Advanced rule %s failed: %s", rule.__name__, exc)
    return results
