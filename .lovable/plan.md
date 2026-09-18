# Payload Capture Suite — Upgrade Plan

The uploaded suite is already advanced and well structured. The work is to complete and finish it, not to rebuild it: keep the existing architecture and fill in what is missing, then hand you a final packaged version.

Two deliverables, built in stages:

1. **The desktop program** (Python/tkinter, Windows) — bug-fixed, feature-expanded, fully offline, restyled in the Cybermon look. Delivered as a downloadable package you run on your PC.
2. **The web suite in this project** — the same interface rebuilt in the browser with the Cybermon design, plus your owner details, social links and the legal/info pages.

## What I found in the uploaded project

- Structure is solid: capture engine, packet parser, flow tracker, detection rules, SQLite evidence store, PDF/HTML/CSV/JSON reports, Windows firewall control, startup health checks, and a test suite.
- No API keys are used anywhere, so "no keys" is already true and will stay true.
- Every non-interface module loads cleanly. The interface modules could not be loaded here because this machine has no graphical toolkit installed — that is an environment limit, not a fault in your code, so the screen-level bug hunt happens through code analysis plus your own run on Windows.
- Firewall control is Windows-only by design; that stays, with a clear message on other systems.
- Current look is a flat GitHub-dark palette; the Cybermon reference uses a deeper five-level palette, one blue accent and four status colours.

I have not yet confirmed specific defects line by line, so the first step of stage 1 is a full audit that produces a written bug list before any fix.

## Stage 1 — Desktop program: audit and fix

- Run automated checks (unused/undefined names, unreachable code, exception handling, thread safety around the capture queue, SQLite access from background threads, file-handle leaks) and read every window file.
- Produce a bug list, then fix each item and record it in a changelog.
- Harden: no crash on missing capture driver, no crash on malformed packets or corrupt capture files, safe shutdown of the capture thread, database write retries.
- Make the existing test suite run green and extend it to cover fixed bugs.

## Stage 2 — Desktop program: offline intelligence and new features

Everything ships inside the app from local data files; no internet calls at all.

- Local IP intelligence: private/reserved/multicast classification, well-known port and service naming, bundled offline network-block and organisation hints.
- Deeper detection: expanded rule set, weighted risk scoring, technique tagging, plus beaconing, port-scan, data-exfiltration-volume and unusual-payload-entropy detection.
- Reporting: richer case report with executive summary, charts, evidence hashes and a chain-of-custody log.
- Live dashboards: real-time throughput and protocol charts, top talkers, alert stream, session timeline.
- Case/session management, saved filters, global search, bookmarking and annotation of packets.

## Stage 3 — Desktop program: new interface

- New shared theme built from the Cybermon tokens: five background depths, three border weights, three text levels, one blue accent plus four status colours, monospace for data and proportional for labels.
- Sidebar navigation with icon rail, top toolbar with live status, card-based panels, elevated inspector for packet detail, consistent tables with severity colouring.
- Restyle every window against the new theme; add an owner/About screen and links to the legal pages.

## Stage 4 — Web suite in this project

- Dark Cybermon design system in the project stylesheet (exact token values from your reference).
- Pages: Dashboard, Live Capture, Packets, Flows, Alerts, DNS, IP Intelligence, Firewall, Timeline, Reports, Search, Settings.
- Rich realistic sample data driving live-feeling charts and tables so the interface is fully explorable in the browser. Real traffic capture is not possible in a browser — that stays a desktop-only capability, stated plainly in the app.
- Owner section: Avimanyu Singh Chauhan, rockniraj311@gmail.com, with social icons linking to @avimanyusingh53.
- Separate pages: Privacy Policy, Disclaimer, Do's and Don'ts, License, Terms, Legal Use & Compliance, Credits.

## Stage 5 — Packaging and handover

- Update requirements, build script, installer script, README and troubleshooting guide.
- Package the upgraded desktop program as a downloadable archive with run instructions.

## Technical notes

- Desktop: Python 3.10+, tkinter/ttk, scapy for capture and PCAP, reportlab for PDF, SQLite for evidence. Pure-Python and standard-library only otherwise, so the build stays offline and keyless.
- Web: TanStack Start with Tailwind v4 tokens in `src/styles.css`, one route file per page, `lucide-react` icons, `recharts` charts, and per-page metadata. No backend needed — data is bundled locally.
- The desktop program cannot run inside this preview; verification of its screens happens on your Windows machine, with the code-level checks and tests run here.

## Notes

The legal pages will be written as general-purpose templates for a security tool. They are not legal advice — review them before publishing.
