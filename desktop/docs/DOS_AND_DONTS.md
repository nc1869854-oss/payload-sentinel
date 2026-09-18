# Do's and Don'ts — Payload Capture Suite

Owner: Avimanyu Singh Chauhan — rockniraj311@gmail.com — @avimanyusingh53

## Do

- **Do get authorisation in writing** before capturing on any network that is
  not your own, and keep it with the case file.
- **Do run as administrator** when you need live capture or firewall control;
  both require elevated rights.
- **Do install the capture driver** (Npcap on Windows) before expecting live
  traffic. Everything else works without it.
- **Do name your sessions** after the case or incident so reports are traceable
  months later.
- **Do verify every alert** in the packet and flow views before acting on it.
- **Do hash and export evidence** as soon as a capture is finished, and store
  the export on separate media.
- **Do annotate what you find** with notes as you go; they appear in reports and
  save hours later.
- **Do prefer PCAP export** when handing work to another analyst; it keeps the
  original bytes intact.
- **Do delete captures** once the investigation that justified them is closed.
- **Do keep the tool offline**; it needs no internet and is safer without it.

## Don't

- **Don't capture on public, shared, employer or customer networks** without
  explicit authority. This is the single fastest way to commit a crime with a
  defensive tool.
- **Don't treat an alert as proof.** Heuristics flag patterns, not intent.
- **Don't block addresses on production networks** without change approval; a
  wrong rule can take services down.
- **Don't store evidence databases unencrypted** on shared drives; captures can
  contain credentials and private messages.
- **Don't edit `data/evidence.db` by hand.** Manual edits destroy the integrity
  of the audit trail and the evidence hashes.
- **Don't share raw captures publicly**, including in bug reports or forums;
  redact first.
- **Don't run capture indefinitely** on a busy interface without a packet limit;
  the database and disk will fill.
- **Don't rely on this tool alone** for monitoring a production environment.
- **Don't assume encrypted traffic is safe** or that plaintext traffic is
  malicious; both need context.
- **Don't redistribute the software** without permission from the owner.

## Quick pre-capture checklist

1. Authorisation documented and in reach.
2. Correct interface selected and packet limit set.
3. Session named after the case.
4. Running with administrator rights.
5. Storage location has free space and is encrypted.
