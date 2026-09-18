# Disclaimer — Payload Capture Suite

Owner: Avimanyu Singh Chauhan — rockniraj311@gmail.com — @avimanyusingh53

## 1. Purpose

Payload Capture Suite is a defensive analysis and educational tool. It is built
for network owners, administrators, students and authorised security
professionals who need to understand traffic on networks they are responsible
for.

## 2. Authorisation is your responsibility

Intercepting network traffic without authorisation is a criminal offence in most
countries. Running this software on a network you do not own or administer,
without documented permission, may expose you to criminal and civil liability.
The author provides the tool; you carry sole responsibility for how it is used.

## 3. Automated findings are hints, not verdicts

Alerts produced by the detection rules are based on statistical heuristics. They
can be wrong in both directions:

- **False positives** — legitimate software such as updaters, backups and
  monitoring agents can look exactly like beaconing or scanning.
- **False negatives** — a careful attacker can stay under every threshold in
  this tool.

Never take disciplinary, legal or containment action on an automated finding
alone. Verify with independent evidence and human judgement.

## 4. Not a replacement for professional security tooling

This suite does not replace an intrusion detection system, an endpoint
protection product, a SIEM, or a professional incident-response engagement. It
has no signature feed, no deep packet inspection of encrypted traffic, and no
ability to decrypt TLS.

## 5. Evidence handling

Hashing and the audit log are provided to support chain of custody, but
admissibility depends entirely on your own procedures, authorisation and local
law. Consult qualified counsel before relying on output in proceedings.

## 6. Firewall controls

The blocking features change your operating system firewall and require
administrator rights. An incorrect rule can cut off legitimate services,
including remote access to the machine itself. Review every rule before
applying it.

## 7. No warranty

The software is provided "as is" without warranty of any kind. The author is not
liable for any loss, damage, downtime, data loss or legal consequence arising
from its use.

---

This document is a general template and not legal advice.
