/**
 * Deterministic demonstration dataset for the console.
 *
 * The desktop program fills these same shapes from a live adapter or a PCAP
 * file. Here the numbers are generated from a fixed seed so every reload,
 * every server render and every chart agrees with the tables beside it.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Risk = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
export type Direction = "OUTGOING" | "INCOMING" | "INTERNAL";

/* ── deterministic pseudo-random source ──────────────────────────────────── */

function makeRandom(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

const rand = makeRandom(20260918);
const pick = <T,>(items: readonly T[]): T =>
  items[Math.floor(rand() * items.length)]!;
const between = (low: number, high: number) =>
  Math.floor(low + rand() * (high - low + 1));

/* ── session ─────────────────────────────────────────────────────────────── */

export const SESSION = {
  id: "PCS-2026-0918-014",
  name: "Workstation WS-114 — suspected call-home",
  analyst: "Avimanyu Singh Chauhan",
  adapter: "Intel(R) Wi-Fi 6E AX211 160MHz",
  source: "Live adapter capture",
  startedAt: "2026-09-18T22:04:11",
  durationSeconds: 5_284,
  filter: "not (port 137 or port 138)",
  evidenceItems: 23,
  notes: 9,
  integrity: "SHA-256 verified",
} as const;

const HOST = "192.168.1.114";
const GATEWAY = "192.168.1.1";

const INTERNAL_PEERS = [
  "192.168.1.1",
  "192.168.1.7",
  "192.168.1.22",
  "192.168.1.45",
  "192.168.1.88",
  "192.168.1.201",
];

type RemoteHost = {
  ip: string;
  host: string;
  org: string;
  country: string;
  risk: Risk;
};

export const REMOTE_HOSTS: RemoteHost[] = [
  { ip: "203.0.113.47", host: "sync-node-4.cdn-relay.net", org: "Unallocated / test range", country: "—", risk: "CRITICAL" },
  { ip: "198.51.100.23", host: "static-23.hosted-metrics.io", org: "Unallocated / test range", country: "—", risk: "HIGH" },
  { ip: "104.18.32.115", host: "assets.cloudfront-edge.net", org: "Cloudflare", country: "US", risk: "LOW" },
  { ip: "142.250.192.78", host: "www.google.com", org: "Google", country: "US", risk: "LOW" },
  { ip: "13.107.42.14", host: "outlook.office365.com", org: "Microsoft", country: "US", risk: "LOW" },
  { ip: "52.94.236.248", host: "s3.eu-west-1.amazonaws.com", org: "Amazon", country: "IE", risk: "MEDIUM" },
  { ip: "140.82.113.4", host: "github.com", org: "GitHub", country: "US", risk: "LOW" },
  { ip: "1.1.1.1", host: "one.one.one.one", org: "Cloudflare", country: "US", risk: "LOW" },
  { ip: "185.199.108.153", host: "pages.github.io", org: "GitHub", country: "US", risk: "LOW" },
  { ip: "91.189.91.42", host: "archive.ubuntu.com", org: "Canonical", country: "GB", risk: "LOW" },
];

/* ── packets ─────────────────────────────────────────────────────────────── */

export type Packet = {
  number: number;
  time: string;
  direction: Direction;
  protocol: string;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  size: number;
  payloadSize: number;
  entropy: number;
  risk: Risk;
  flowId: string;
  summary: string;
  stack: string;
  payloadPreview: string;
};

const PROTOCOLS = ["TCP", "TLS", "UDP", "DNS", "HTTP", "ICMP", "QUIC", "ARP"] as const;

const SUMMARIES: Record<string, string[]> = {
  TCP: ["[SYN] Seq=0 Win=64240", "[ACK] Seq=1 Ack=1 Win=2048", "[PSH, ACK] Len=1380", "[FIN, ACK] Seq=94 Ack=71"],
  TLS: ["Client Hello (SNI set)", "Server Hello, Certificate", "Application Data", "Change Cipher Spec"],
  UDP: ["Len=512 opaque payload", "Len=1232 opaque payload", "Len=98 keep-alive"],
  DNS: ["Standard query A", "Standard query response A", "Standard query AAAA", "Standard query TXT"],
  HTTP: ["GET /api/v2/ping HTTP/1.1", "POST /collect HTTP/1.1", "HTTP/1.1 200 OK", "HTTP/1.1 204 No Content"],
  ICMP: ["Echo (ping) request", "Echo (ping) reply", "Destination unreachable"],
  QUIC: ["Initial, DCID length 8", "Handshake", "Protected payload"],
  ARP: ["Who has 192.168.1.1? Tell 192.168.1.114", "192.168.1.1 is at 3c:22:fb:19:aa:0e"],
};

const STACKS: Record<string, string> = {
  TCP: "Ethernet II › IPv4 › TCP",
  TLS: "Ethernet II › IPv4 › TCP › TLS 1.3",
  UDP: "Ethernet II › IPv4 › UDP",
  DNS: "Ethernet II › IPv4 › UDP › DNS",
  HTTP: "Ethernet II › IPv4 › TCP › HTTP",
  ICMP: "Ethernet II › IPv4 › ICMP",
  QUIC: "Ethernet II › IPv4 › UDP › QUIC",
  ARP: "Ethernet II › ARP",
};

const HEX_CHARS = "0123456789abcdef";

function hexPreview(bytes: number): string {
  const rows: string[] = [];
  const count = Math.min(6, Math.max(1, Math.ceil(bytes / 16)));
  for (let row = 0; row < count; row += 1) {
    let hex = "";
    let ascii = "";
    for (let col = 0; col < 16; col += 1) {
      const value = between(32, 126);
      hex += `${HEX_CHARS[value >> 4]}${HEX_CHARS[value & 15]} `;
      ascii += rand() > 0.35 ? String.fromCharCode(value) : ".";
    }
    rows.push(
      `${(row * 16).toString(16).padStart(4, "0")}  ${hex.trim()}  |${ascii}|`,
    );
  }
  return rows.join("\n");
}

function portForProtocol(protocol: string): number {
  switch (protocol) {
    case "TLS":
      return 443;
    case "HTTP":
      return 80;
    case "DNS":
      return 53;
    case "QUIC":
      return 443;
    case "ICMP":
    case "ARP":
      return 0;
    default:
      return pick([22, 445, 3389, 8443, 8080, 1883, 5222, 993]);
  }
}

function riskFor(protocol: string, port: number, remoteRisk: Risk, payload: number): Risk {
  if (remoteRisk === "CRITICAL") return "CRITICAL";
  if (protocol === "HTTP" && payload > 1200) return "HIGH";
  if ([445, 3389, 22, 23].includes(port)) return "HIGH";
  if (remoteRisk === "HIGH" || payload > 4000) return "MEDIUM";
  if (protocol === "ARP" || protocol === "ICMP") return "NONE";
  return "LOW";
}

export const PACKETS: Packet[] = Array.from({ length: 420 }, (_, index) => {
  const start = new Date(SESSION.startedAt).getTime();
  const time = new Date(start + index * between(400, 3_100));
  const protocol = pick(PROTOCOLS);
  const isInternal = rand() < 0.22;
  const remote = pick(REMOTE_HOSTS);
  const outgoing = rand() < 0.62;
  const peer = isInternal ? pick(INTERNAL_PEERS) : remote.ip;
  const port = portForProtocol(protocol);
  const payloadSize = protocol === "ARP" ? 0 : between(0, protocol === "HTTP" ? 5_400 : 1_460);
  const ephemeral = between(49_152, 65_535);

  const entropy =
    protocol === "TLS" || protocol === "QUIC"
      ? 7.5 + rand() * 0.45
      : protocol === "HTTP" && rand() < 0.2
        ? 7.4 + rand() * 0.5
        : 3 + rand() * 3;

  return {
    number: index + 1,
    time: time.toISOString().slice(11, 23),
    direction: isInternal ? "INTERNAL" : outgoing ? "OUTGOING" : "INCOMING",
    protocol,
    srcIp: outgoing || isInternal ? HOST : peer,
    dstIp: outgoing || isInternal ? peer : HOST,
    srcPort: port === 0 ? null : outgoing ? ephemeral : port,
    dstPort: port === 0 ? null : outgoing ? port : ephemeral,
    size: payloadSize + between(40, 66),
    payloadSize,
    entropy: Number(entropy.toFixed(2)),
    risk: riskFor(protocol, port, isInternal ? "LOW" : remote.risk, payloadSize),
    flowId: `F-${String(between(1, 48)).padStart(3, "0")}`,
    summary: pick(SUMMARIES[protocol] ?? ["Payload"]),
    stack: STACKS[protocol] ?? "Ethernet II › IPv4",
    payloadPreview: hexPreview(payloadSize),
  };
});

/* ── flows ───────────────────────────────────────────────────────────────── */

export type Flow = {
  id: string;
  protocol: string;
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  remoteHost: string;
  packets: number;
  bytesOut: number;
  bytesIn: number;
  firstSeen: string;
  lastSeen: string;
  direction: Direction;
  risk: Risk;
  state: "ESTABLISHED" | "CLOSED" | "HALF-OPEN" | "RESET";
};

export const FLOWS: Flow[] = Array.from({ length: 48 }, (_, index) => {
  const remote = REMOTE_HOSTS[index % REMOTE_HOSTS.length]!;
  const protocol = pick(["TCP", "TLS", "UDP", "QUIC", "DNS"] as const);
  const packets = between(6, 2_400);
  const bytesOut = packets * between(80, 1_400);
  const exfil = remote.risk === "CRITICAL" || remote.risk === "HIGH";
  const start = new Date(SESSION.startedAt).getTime() + index * 63_000;

  return {
    id: `F-${String(index + 1).padStart(3, "0")}`,
    protocol,
    localIp: HOST,
    localPort: between(49_152, 65_535),
    remoteIp: remote.ip,
    remotePort: portForProtocol(protocol) || 443,
    remoteHost: remote.host,
    packets,
    bytesOut: exfil ? bytesOut * 6 : bytesOut,
    bytesIn: exfil ? Math.floor(bytesOut * 0.05) : packets * between(120, 2_200),
    firstSeen: new Date(start).toISOString().slice(11, 19),
    lastSeen: new Date(start + between(4_000, 900_000)).toISOString().slice(11, 19),
    direction: rand() < 0.75 ? "OUTGOING" : "INCOMING",
    risk: remote.risk,
    state: pick(["ESTABLISHED", "CLOSED", "HALF-OPEN", "RESET"] as const),
  };
});

/* ── findings ────────────────────────────────────────────────────────────── */

export type Finding = {
  id: string;
  severity: Severity;
  confidence: number;
  technique: string;
  title: string;
  description: string;
  evidence: string[];
  recommendation: string;
  relatedIp: string;
  relatedFlow: string;
  detectedAt: string;
  status: "OPEN" | "TRIAGED" | "ESCALATED";
};

export const FINDINGS: Finding[] = [
  {
    id: "A-001",
    severity: "CRITICAL",
    confidence: 96,
    technique: "T1071 — Application Layer Protocol (C2)",
    title: "Regular beaconing to 203.0.113.47",
    description:
      "This machine contacted the same outside address 84 times at an almost perfectly even 60-second spacing. Software used by people has irregular timing; a fixed heartbeat like this is how remote-control tools check in for orders.",
    evidence: [
      "Contacts: 84 over 1h 24m",
      "Average gap: 60.0s (variation 0.7s)",
      "Destination port: 8443/TCP (not a registered service)",
      "Payload high-entropy on every contact",
    ],
    recommendation:
      "Isolate the machine from the network, preserve this session as evidence, then block the address at the firewall and look for the program making the connection.",
    relatedIp: "203.0.113.47",
    relatedFlow: "F-001",
    detectedAt: "22:41:09",
    status: "ESCALATED",
  },
  {
    id: "A-002",
    severity: "HIGH",
    confidence: 88,
    technique: "T1041 — Exfiltration Over C2 Channel",
    title: "Large one-way upload to 203.0.113.47",
    description:
      "412 MB left this machine towards a single outside address while only 19 MB came back. Normal browsing downloads far more than it uploads, so a heavily one-sided transfer suggests data is being copied out.",
    evidence: [
      "Sent: 412.6 MB",
      "Received: 19.1 MB",
      "Ratio out:in — 21.6 : 1",
      "Transfer window: 22:31 – 23:14",
    ],
    recommendation:
      "Identify what was uploaded before the machine is reimaged. Keep the packet payloads attached to this session for the investigation record.",
    relatedIp: "203.0.113.47",
    relatedFlow: "F-001",
    detectedAt: "23:14:52",
    status: "ESCALATED",
  },
  {
    id: "A-003",
    severity: "HIGH",
    confidence: 74,
    technique: "T1071.004 — DNS",
    title: "Possible DNS tunnelling via hosted-metrics.io",
    description:
      "Name lookups for this domain carry unusually long, random-looking labels. Address lookups are rarely blocked by firewalls, which makes them a convenient hiding place for smuggled data.",
    evidence: [
      "Queries: 316 to one domain",
      "Longest label: 58 characters",
      "Average label randomness: 4.6 bits/char",
      "Almost no repeated names",
    ],
    recommendation:
      "Point the machine at a controlled resolver that logs queries, and treat the domain as hostile until proven otherwise.",
    relatedIp: "198.51.100.23",
    relatedFlow: "F-002",
    detectedAt: "22:58:31",
    status: "TRIAGED",
  },
  {
    id: "A-004",
    severity: "HIGH",
    confidence: 81,
    technique: "T1021.002 — SMB/Windows Admin Shares",
    title: "File-sharing traffic to six internal machines",
    description:
      "This machine opened Windows file-sharing connections to six other computers within a few minutes. A single workstation rarely needs that, and it is the classic spreading pattern for ransomware.",
    evidence: [
      "Destination port: 445/TCP",
      "Internal machines contacted: 6",
      "Window: 4m 12s",
      "Half-open connections: 3",
    ],
    recommendation:
      "Check whether file sharing is required on this machine at all. Block port 445 outbound from workstations if it is not.",
    relatedIp: "192.168.1.22",
    relatedFlow: "F-014",
    detectedAt: "22:19:47",
    status: "OPEN",
  },
  {
    id: "A-005",
    severity: "MEDIUM",
    confidence: 80,
    technique: "T1046 — Network Service Discovery",
    title: "Port scan pattern from 192.168.1.88",
    description:
      "One machine on the local network tried 41 different ports on a single target in under a minute. That is a scan looking for something to attack, not normal use.",
    evidence: [
      "Ports tried: 41",
      "Target: 192.168.1.114",
      "Duration: 48s",
      "Responses: 2 open, 39 refused",
    ],
    recommendation:
      "Find out who owns 192.168.1.88. If the scan was not an authorised test, treat that machine as compromised too.",
    relatedIp: "192.168.1.88",
    relatedFlow: "F-021",
    detectedAt: "22:33:02",
    status: "OPEN",
  },
  {
    id: "A-006",
    severity: "MEDIUM",
    confidence: 69,
    technique: "T1573 — Encrypted Channel",
    title: "Scrambled payloads on a plaintext port",
    description:
      "Traffic on port 80 should be readable web requests, but these payloads are as random as encrypted data. Something is hiding a secure channel on a port firewalls usually leave open.",
    evidence: [
      "Packets affected: 57",
      "Average randomness: 7.83 of 8.0",
      "Port: 80/TCP",
      "No HTTP request line present",
    ],
    recommendation:
      "Inspect the payloads in the packet view and confirm which program owns the connection before allowing it again.",
    relatedIp: "198.51.100.23",
    relatedFlow: "F-002",
    detectedAt: "22:47:20",
    status: "TRIAGED",
  },
  {
    id: "A-007",
    severity: "MEDIUM",
    confidence: 63,
    technique: "T1095 — Non-Application Layer Protocol",
    title: "Unexpected protocol on the HTTPS port",
    description:
      "Nine conversations used port 443 with something other than TCP. Secure web traffic is always TCP, so this is another way of slipping past simple firewall rules.",
    evidence: ["Conversations: 9", "Protocols seen: UDP, raw IP", "Port: 443"],
    recommendation:
      "Review these conversations individually; legitimate QUIC traffic will show a proper handshake, tunnels will not.",
    relatedIp: "52.94.236.248",
    relatedFlow: "F-006",
    detectedAt: "23:02:44",
    status: "OPEN",
  },
  {
    id: "A-008",
    severity: "LOW",
    confidence: 58,
    technique: "T1029 — Scheduled Transfer",
    title: "Sustained activity outside working hours",
    description:
      "3,184 packets were captured between 22:00 and 06:00. Some of this is normal background updating, but it is worth confirming nobody is using the machine while it should be idle.",
    evidence: [
      "Off-hours packets: 3,184 (74% of session)",
      "Quiet-hours window: 22:00 – 06:00",
      "Busiest hour: 23:00",
    ],
    recommendation:
      "Compare against the machine's update schedule. Anything unaccounted for deserves a second look.",
    relatedIp: HOST,
    relatedFlow: "F-030",
    detectedAt: "23:59:00",
    status: "TRIAGED",
  },
  {
    id: "A-009",
    severity: "INFO",
    confidence: 100,
    technique: "—",
    title: "Session integrity verified",
    description:
      "Every captured packet and every evidence item in this session still matches the fingerprint recorded when it was saved. Nothing has been altered since collection.",
    evidence: [
      "Packets hashed: 4,284",
      "Evidence items: 23",
      "Algorithm: SHA-256",
      "Mismatches: 0",
    ],
    recommendation: "No action needed. Include this check in the exported report.",
    relatedIp: HOST,
    relatedFlow: "—",
    detectedAt: "23:59:12",
    status: "TRIAGED",
  },
];

/* ── risk score ──────────────────────────────────────────────────────────── */

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 25,
  MEDIUM: 12,
  LOW: 5,
  INFO: 0,
};

export function scoreFindings(findings: Finding[]) {
  const raw = findings.reduce(
    (total, finding) =>
      total + SEVERITY_WEIGHT[finding.severity] * (finding.confidence / 100),
    0,
  );
  const score = Math.min(100, Math.round(100 * (1 - Math.exp(-raw / 60))));
  const band =
    score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 35 ? "MEDIUM" : score >= 15 ? "LOW" : "CLEAN";
  return { score, band };
}

export const RISK = scoreFindings(FINDINGS);

export const SEVERITY_COUNTS = FINDINGS.reduce<Record<Severity, number>>(
  (counts, finding) => {
    counts[finding.severity] += 1;
    return counts;
  },
  { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
);

/* ── DNS ─────────────────────────────────────────────────────────────────── */

export type DnsRecord = {
  time: string;
  query: string;
  type: "A" | "AAAA" | "TXT" | "CNAME" | "MX";
  answer: string;
  resolver: string;
  count: number;
  verdict: "OK" | "SUSPICIOUS" | "BLOCKED";
  note: string;
};

export const DNS_RECORDS: DnsRecord[] = [
  { time: "22:04:19", query: "www.google.com", type: "A", answer: "142.250.192.78", resolver: "1.1.1.1", count: 34, verdict: "OK", note: "Well-known search service" },
  { time: "22:05:02", query: "outlook.office365.com", type: "A", answer: "13.107.42.14", resolver: "1.1.1.1", count: 96, verdict: "OK", note: "Mail client polling" },
  { time: "22:11:44", query: "k3f8a91c2e7b4d6a.hosted-metrics.io", type: "TXT", answer: "v=1;d=QUJDREVGR0hJ…", resolver: "1.1.1.1", count: 316, verdict: "SUSPICIOUS", note: "Long random label, TXT answers — tunnelling pattern" },
  { time: "22:19:07", query: "sync-node-4.cdn-relay.net", type: "A", answer: "203.0.113.47", resolver: "1.1.1.1", count: 84, verdict: "BLOCKED", note: "Beacon destination; blocked after triage" },
  { time: "22:26:31", query: "github.com", type: "A", answer: "140.82.113.4", resolver: "1.1.1.1", count: 12, verdict: "OK", note: "Developer tooling" },
  { time: "22:34:58", query: "s3.eu-west-1.amazonaws.com", type: "A", answer: "52.94.236.248", resolver: "1.1.1.1", count: 41, verdict: "SUSPICIOUS", note: "Large uploads followed this lookup" },
  { time: "22:41:12", query: "archive.ubuntu.com", type: "A", answer: "91.189.91.42", resolver: "1.1.1.1", count: 7, verdict: "OK", note: "Package updates" },
  { time: "22:52:40", query: "assets.cloudfront-edge.net", type: "CNAME", answer: "104.18.32.115", resolver: "1.1.1.1", count: 58, verdict: "OK", note: "Content delivery" },
  { time: "23:03:15", query: "wpad.localdomain", type: "A", answer: "NXDOMAIN", resolver: "192.168.1.1", count: 22, verdict: "SUSPICIOUS", note: "Proxy auto-discovery; spoofable on local networks" },
  { time: "23:18:49", query: "one.one.one.one", type: "AAAA", answer: "2606:4700:4700::1111", resolver: "1.1.1.1", count: 4, verdict: "OK", note: "Resolver self-check" },
];

/* ── timeline ────────────────────────────────────────────────────────────── */

export type TimelineEvent = {
  time: string;
  kind: "CAPTURE" | "FLOW" | "DNS" | "ALERT" | "EVIDENCE" | "FIREWALL" | "NOTE";
  severity: Severity;
  title: string;
  detail: string;
};

export const TIMELINE: TimelineEvent[] = [
  { time: "22:04:11", kind: "CAPTURE", severity: "INFO", title: "Capture started", detail: "Adapter: Intel Wi-Fi 6E AX211 · filter active" },
  { time: "22:11:44", kind: "DNS", severity: "MEDIUM", title: "Unusual name lookup", detail: "58-character random label under hosted-metrics.io" },
  { time: "22:19:47", kind: "ALERT", severity: "HIGH", title: "File-sharing sweep detected", detail: "Port 445 to six internal machines in 4m 12s" },
  { time: "22:26:03", kind: "EVIDENCE", severity: "INFO", title: "Evidence captured", detail: "12 packets attached and hashed (SHA-256)" },
  { time: "22:31:18", kind: "FLOW", severity: "MEDIUM", title: "Long-lived upload began", detail: "F-001 towards 203.0.113.47 on port 8443" },
  { time: "22:33:02", kind: "ALERT", severity: "MEDIUM", title: "Port scan from local machine", detail: "192.168.1.88 tried 41 ports on this host" },
  { time: "22:41:09", kind: "ALERT", severity: "CRITICAL", title: "Beaconing confirmed", detail: "84 contacts at a 60-second heartbeat" },
  { time: "22:47:20", kind: "ALERT", severity: "MEDIUM", title: "Scrambled payload on port 80", detail: "57 packets with encryption-level randomness" },
  { time: "22:55:36", kind: "NOTE", severity: "INFO", title: "Analyst note", detail: "Machine owner confirms no scheduled backup at this hour" },
  { time: "23:09:41", kind: "FIREWALL", severity: "INFO", title: "Outbound block applied", detail: "203.0.113.47 blocked — rule PCS-BLOCK-0007" },
  { time: "23:14:52", kind: "ALERT", severity: "HIGH", title: "Exfiltration volume threshold passed", detail: "412.6 MB out against 19.1 MB in" },
  { time: "23:31:07", kind: "EVIDENCE", severity: "INFO", title: "Evidence bundle sealed", detail: "23 items · chain of custody written" },
  { time: "23:59:12", kind: "CAPTURE", severity: "INFO", title: "Integrity check passed", detail: "4,284 packets verified, 0 mismatches" },
];

/* ── firewall ────────────────────────────────────────────────────────────── */

export type FirewallRule = {
  name: string;
  target: string;
  direction: "Outbound" | "Inbound";
  action: "Block" | "Allow";
  scope: string;
  createdBy: string;
  createdAt: string;
  enabled: boolean;
};

export const FIREWALL_RULES: FirewallRule[] = [
  { name: "PCS-BLOCK-0007", target: "203.0.113.47", direction: "Outbound", action: "Block", scope: "All ports", createdBy: "Alert A-001", createdAt: "23:09:41", enabled: true },
  { name: "PCS-BLOCK-0008", target: "198.51.100.23", direction: "Outbound", action: "Block", scope: "All ports", createdBy: "Alert A-003", createdAt: "23:11:02", enabled: true },
  { name: "PCS-BLOCK-0009", target: "0.0.0.0/0 : 445", direction: "Outbound", action: "Block", scope: "Port 445/TCP", createdBy: "Alert A-004", createdAt: "23:12:20", enabled: false },
  { name: "PCS-ALLOW-0002", target: "192.168.1.0/24", direction: "Inbound", action: "Allow", scope: "Port 3389/TCP", createdBy: "Analyst", createdAt: "22:02:10", enabled: true },
  { name: "PCS-BLOCK-0010", target: "cdn-relay.net", direction: "Outbound", action: "Block", scope: "Name resolution", createdBy: "Analyst", createdAt: "23:22:55", enabled: true },
];

/* ── evidence and reports ────────────────────────────────────────────────── */

export type EvidenceItem = {
  id: string;
  kind: "Packet set" | "Flow record" | "Note" | "Screenshot" | "PCAP slice";
  label: string;
  items: number;
  hash: string;
  addedAt: string;
  addedBy: string;
};

export const EVIDENCE: EvidenceItem[] = [
  { id: "E-001", kind: "Packet set", label: "Beacon contacts 1–84", items: 84, hash: "9f2c…41ab", addedAt: "22:41:30", addedBy: OWNER_SHORT() },
  { id: "E-002", kind: "Flow record", label: "F-001 full conversation record", items: 1, hash: "1d77…c0e2", addedAt: "22:42:02", addedBy: OWNER_SHORT() },
  { id: "E-003", kind: "PCAP slice", label: "22:31–23:14 upload window", items: 2_411, hash: "b845…7f19", addedAt: "23:15:44", addedBy: OWNER_SHORT() },
  { id: "E-004", kind: "Note", label: "Owner interview — no scheduled backup", items: 1, hash: "5ac1…9920", addedAt: "22:55:36", addedBy: OWNER_SHORT() },
  { id: "E-005", kind: "Packet set", label: "Port 80 scrambled payloads", items: 57, hash: "e30f…4d6c", addedAt: "22:48:10", addedBy: OWNER_SHORT() },
  { id: "E-006", kind: "Screenshot", label: "Firewall rule confirmation", items: 1, hash: "77be…2a55", addedAt: "23:10:04", addedBy: OWNER_SHORT() },
];

function OWNER_SHORT() {
  return "A. S. Chauhan";
}

export type ReportTemplate = {
  id: string;
  name: string;
  audience: string;
  sections: string[];
  format: "PDF" | "PDF + JSON" | "JSON" | "CSV";
};

export const REPORT_TEMPLATES: ReportTemplate[] = [
  {
    id: "R-EXEC",
    name: "Executive summary",
    audience: "Management, non-technical",
    sections: ["Risk score", "What happened", "What we did", "What to decide"],
    format: "PDF",
  },
  {
    id: "R-TECH",
    name: "Full technical report",
    audience: "Analysts, IT",
    sections: ["Session metadata", "All findings with evidence", "Flow table", "Packet appendix", "Detection settings"],
    format: "PDF + JSON",
  },
  {
    id: "R-IOC",
    name: "Indicator list",
    audience: "Blocking and hunting",
    sections: ["Addresses", "Domains", "Ports", "Hashes"],
    format: "CSV",
  },
  {
    id: "R-CUSTODY",
    name: "Chain of custody",
    audience: "Legal, compliance",
    sections: ["Evidence inventory", "Hash ledger", "Access log", "Analyst attestation"],
    format: "PDF",
  },
];

/* ── charts ──────────────────────────────────────────────────────────────── */

export const THROUGHPUT = Array.from({ length: 48 }, (_, index) => {
  const minute = index * 2;
  const base = 120 + Math.sin(index / 3) * 60;
  const spike = index > 26 && index < 38 ? 320 : 0;
  return {
    t: `${String(22 + Math.floor(minute / 60)).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}`,
    out: Math.round(base + spike + rand() * 40),
    in: Math.round(base * 0.7 + rand() * 30),
  };
});

export const PROTOCOL_MIX = (() => {
  const counts = new Map<string, number>();
  for (const packet of PACKETS) {
    counts.set(packet.protocol, (counts.get(packet.protocol) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
})();

export const TOP_TALKERS = (() => {
  const totals = new Map<string, number>();
  for (const flow of FLOWS) {
    totals.set(flow.remoteIp, (totals.get(flow.remoteIp) ?? 0) + flow.bytesOut + flow.bytesIn);
  }
  return [...totals.entries()]
    .map(([ip, bytes]) => ({
      ip,
      bytes,
      host: REMOTE_HOSTS.find((host) => host.ip === ip)?.host ?? ip,
      risk: REMOTE_HOSTS.find((host) => host.ip === ip)?.risk ?? "LOW",
    }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 8);
})();

/* ── stats ───────────────────────────────────────────────────────────────── */

export const STATS = {
  packets: 4_284,
  flows: FLOWS.length,
  bytes: FLOWS.reduce((total, flow) => total + flow.bytesOut + flow.bytesIn, 0),
  payloadBytes: PACKETS.reduce((total, packet) => total + packet.payloadSize, 0),
  dnsQueries: DNS_RECORDS.reduce((total, record) => total + record.count, 0),
  uniqueRemotes: REMOTE_HOSTS.length,
  gateway: GATEWAY,
  host: HOST,
};

/* ── formatting helpers ──────────────────────────────────────────────────── */

export function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}

export function formatNumber(value: number): string {
  return value.toLocaleString("en-US");
}

export function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  return `${hours}h ${String(minutes).padStart(2, "0")}m ${String(rest).padStart(2, "0")}s`;
}
