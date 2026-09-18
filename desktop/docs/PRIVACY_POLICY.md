# Privacy Policy — Payload Capture Suite

Last updated: 2026
Owner: Avimanyu Singh Chauhan — rockniraj311@gmail.com — @avimanyusingh53

## The short version

Payload Capture Suite runs entirely on your computer. It has no accounts, no
API keys, no analytics and no telemetry. Nothing you capture is ever sent
anywhere by this software.

## 1. What the software stores

All data stays on your machine, in the application folder:

| Location | Contents |
| --- | --- |
| `data/evidence.db` | Sessions, packets, flows, alerts, notes, audit log |
| `logs/` | Application log for troubleshooting |
| `exports/` | Reports and exports you generate |
| `config/settings.json` | Your preferences |

Captured traffic can contain personal and sensitive data, including addresses
you visited, credentials sent over unencrypted protocols, and message content.
You are the sole controller of that data.

## 2. What the software sends out

Nothing. There are no outbound connections, update checks, crash reports, usage
statistics or cloud lookups. Threat rules and address intelligence ship inside
the application as local data files.

## 3. Your responsibilities as the operator

- Capture only on networks you own or are authorised in writing to monitor.
- Tell people who use those networks that monitoring takes place, where the law
  requires it.
- Keep evidence files encrypted at rest and restricted to those who need them.
- Delete captures once the investigation that justified them is closed.

## 4. Retention and deletion

The software never deletes your data automatically. Removing a session from the
Sessions screen deletes its packets, flows, alerts and notes from the local
database. Deleting the `data/` folder removes everything.

## 5. Children

This is a professional security tool and is not intended for use by children.

## 6. Changes

Changes to this policy are published with new versions of the software. The
"last updated" date above marks the current revision.

## 7. Contact

Questions about this policy: rockniraj311@gmail.com

---

This document is a general template and not legal advice.
