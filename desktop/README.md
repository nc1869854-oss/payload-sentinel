# Payload Capture Suite

**Network Investigation & Evidence Platform**

> Capture → Understand → Correlate → Investigate → Preserve → Report → Respond

Payload Capture Suite is an offline-first network investigation and evidence platform that captures or imports network traffic, organises it into packets and flows, analyses payload characteristics and communication patterns, produces explainable findings, reconstructs timelines, preserves evidence with cryptographic hashes, and generates professional investigation reports.

It is **not** a Wireshark clone. It is built around analyst workflow, automatic organisation, evidence preservation, and explainable findings — designed to work **alongside** Wireshark, not replace it.

---

## What it does

| Capability | Description |
|---|---|
| **Live capture** | Scapy-based packet capture on any local interface |
| **PCAP import** | Load existing `.pcap`/`.pcapng` files through the same analysis pipeline |
| **Flow analysis** | Groups packets into bidirectional conversations automatically |
| **DNS analysis** | Dedicated DNS query/response viewer with frequency and signal analysis |
| **Rule engine** | 9 deterministic heuristic rules generate explainable findings — no AI, no cloud |
| **Finding lifecycle** | NEW → INVESTIGATING → CONFIRMED → DISMISSED → RESOLVED |
| **Timeline** | Chronological event reconstruction from DNS, TCP, TLS, UDP, ICMP activity |
| **IP investigation** | Classification, reverse DNS, per-IP session statistics |
| **Evidence hashing** | SHA-256 of every exported file with in-app verification |
| **Reports** | HTML, PDF (ReportLab), CSV (zipped), JSON — all from the same session data |
| **Global search** | Query across packets, flows, findings, notes, and timeline simultaneously |
| **Audit trail** | Every analyst action logged chronologically and exportable |
| **Firewall controls** | Windows Firewall block/unblock via `netsh` (opt-in, admin required) |
| **SQLite database** | All session data persists between runs |

---

## Architecture

```
Scapy Capture Thread
        │
        ▼ (raw Scapy packets)
Thread-safe Queue
        │
        ▼ (parsed dicts via packets/parser.py)
Flow Tracker  ──────────────────────────► FlowTracker (in-memory)
        │
        ▼
SQLite Database (evidence/database.py)
        │
        ├── sessions          ├── packets
        ├── flows             ├── alerts / findings
        ├── timeline_events   ├── notes
        ├── action_log        └── evidence_files
        │
        ▼
UI Main Thread (Tkinter, via root.after())
        │
        ├── CaptureWindow      ├── FlowWindow
        ├── AlertsWindow       ├── TimelineWindow
        ├── DnsWindow          ├── IPWindow
        ├── ReportWindow       ├── SearchWindow
        ├── AuditWindow        └── SettingsWindow
```

The capture thread **never touches Tkinter widgets directly**. All UI updates go through `root.after()` on the main thread.

---

## Module map

```
PayloadCaptureSuite/
├── main.py                    Entry point
├── requirements.txt
│
├── config/
│   ├── theme.py               Shared colour/font/spacing constants
│   ├── settings.py            User settings with load/save
│   └── logger.py              Central rotating log (logs/payloadcapture.log)
│
├── core/
│   ├── session.py             InvestigationSession — central state object
│   └── startup.py             Health checks run before the UI opens
│
├── capture/
│   ├── engine.py              Scapy live capture thread + queue
│   ├── filters.py             User-friendly → BPF filter translation
│   └── pcap.py                PCAP import (PcapImporter) and export
│
├── packets/
│   ├── parser.py              Scapy packet → clean Python dict
│   └── payload.py             ASCII/HEX/entropy/SHA-256 analysis
│
├── flows/
│   └── tracker.py             Groups packets into bidirectional flows
│
├── analysis/
│   ├── rules.py               9 deterministic heuristic finding rules
│   └── statistics.py          Protocol distribution, top IPs, traffic over time
│
├── investigation/
│   ├── ip.py                  IP classification, reverse DNS, session aggregation
│   └── timeline.py            Chronological event reconstruction
│
├── evidence/
│   ├── database.py            All SQLite operations (single module)
│   ├── sessions.py            Session ID generation, time formatting
│   └── hashing.py             SHA-256 file hashing + verification
│
├── reports/
│   ├── report_builder.py      Assembles report_data dict from session
│   ├── html_report.py         Self-contained HTML with embedded CSS
│   ├── pdf_report.py          ReportLab PDF (graceful fallback if missing)
│   ├── csv_report.py          Zip archive: flows/findings/timeline/notes CSVs
│   └── json_report.py         Complete machine-readable export
│
├── firewall/
│   └── windows_firewall.py    netsh integration (Windows only, opt-in)
│
├── ui/
│   ├── widgets.py             Reusable components (cards, tables, buttons)
│   ├── main_window.py         Dashboard — answers 5 investigation questions
│   ├── capture_window.py      Live capture workstation
│   ├── flow_window.py         Flow investigation
│   ├── dns_window.py          DNS query analysis
│   ├── timeline_window.py     Chronological event view
│   ├── alerts_window.py       Findings with lifecycle state management
│   ├── ip_window.py           Per-IP investigation
│   ├── report_window.py       Report generation and evidence management
│   ├── search_window.py       Global search across all session data
│   ├── audit_window.py        Investigation audit trail
│   ├── stats_panel.py         Reusable statistics panel
│   ├── stats_window.py        Statistics standalone window
│   ├── pcap_window.py         PCAP import/export
│   ├── settings_window.py     Application settings
│   ├── firewall_dialog.py     Block/unblock confirmation dialogs
│   └── startup_dialog.py      Startup health check display
│
├── tests/
│   └── test_suite.py          64-test suite (no live traffic needed)
│
├── build/
│   └── app.manifest           UAC elevation manifest for Windows exe
│
├── PayloadCaptureSuite.spec   PyInstaller build specification
├── PayloadCaptureSuite.nsi    NSIS installer script
├── build.bat                  One-click build script (Windows)
└── TROUBLESHOOTING.md
```

---

## Installation

### Running from source

```bash
# 1. Clone or extract the project
cd PayloadCaptureSuite

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. On Windows: install Npcap for live capture
#    https://npcap.com  (tick "WinPcap API-compatible mode")

# 4. Run (as Administrator on Windows for live capture)
python main.py
```

### Building a Windows installer

```bash
# Prerequisites (install once):
#   - NSIS 3.x:   https://nsis.sourceforge.io/Download
#   - Npcap OEM:  https://npcap.com/dist/npcap-1.79-oem.exe
#                 → place at installer\npcap-1.79-oem.exe

# Build everything in one step:
build.bat

# Output: PayloadCaptureSuite_Setup.exe
# End users need nothing else — just run the installer.
```

---

## Analyst workflow

```
1.  Launch application (run as Administrator)
2.  NEW SESSION
3.  CAPTURE  →  select interface  →  START CAPTURE
    — or —
4.  CAPTURE  →  IMPORT PCAP  →  browse to .pcap file
5.  Observe packets, flows building in real time
6.  ALERTS  →  RE-ANALYSE  →  review findings
7.  Click a finding  →  set state (INVESTIGATING / CONFIRMED / DISMISSED)
8.  DNS  →  review query patterns
9.  TIMELINE  →  reconstruct event sequence
10. IP ANALYSIS  →  profile specific addresses
11. SEARCH  →  cross-query any keyword
12. Add analyst notes to packets, flows, and findings
13. EVIDENCE  →  GENERATE HTML / PDF / CSV / JSON
14. Hashes are recorded automatically
15. AUDIT TRAIL  →  review all actions taken
16. CLOSE SESSION
```

---

## Findings and severity

The rule engine generates **findings** — not verdicts. A finding is an observation that warrants investigation.

| Severity | Meaning |
|---|---|
| CRITICAL | Requires immediate attention |
| HIGH | Strong investigation priority |
| MEDIUM | Notable pattern — investigate when possible |
| LOW | Informational — review in context |
| INFO | Background observation |

Every finding includes:
- What was observed
- The specific evidence that triggered it
- A concrete recommendation
- The related IP or flow

**The application never says "this is malicious".** The analyst makes that determination.

---

## Security and authorisation

This application is designed for:
- Systems the analyst owns
- Networks the analyst administers  
- Authorised security testing environments
- Incident response with explicit written authorisation

Network monitoring laws vary by jurisdiction. You are responsible for compliance.

---

## Running the tests

```bash
python tests/test_suite.py
# or
python -m pytest tests/test_suite.py -v
```

64 tests covering: payload analysis, packet parsing, IP classification, flow tracking, rule engine, statistics, timeline, database operations, hashing, filter translation, session state, and report generation.

No live network traffic is required — all tests use synthetic data.

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common build and runtime problems.

Logs are written to `logs/payloadcapture.log` (rotating, 5 MB max, 3 backups).
