# Credits — Payload Capture Suite

## Author

**Avimanyu Singh Chauhan** — owner, architect and lead developer
Email: rockniraj311@gmail.com
Social: @avimanyusingh53

## Third-party components

| Component | Purpose | Licence |
| --- | --- | --- |
| Python | Runtime | PSF License |
| Tkinter / Tcl-Tk | Desktop interface | Tcl/Tk BSD-style licence |
| Scapy | Packet capture, parsing and PCAP handling | GPL-2.0 |
| ReportLab | PDF report generation | BSD-3-Clause |
| SQLite | Embedded evidence database | Public domain |
| Npcap (Windows, optional) | Packet capture driver | Npcap licence — install separately |
| PyInstaller (build only) | Windows executable packaging | GPL-2.0 with exception |
| NSIS (build only) | Windows installer | zlib/libpng licence |

Scapy is licensed under the GPL-2.0. If you distribute a build that bundles
Scapy, your distribution must comply with that licence.

## Standards and references

- RFC 1918 / RFC 6890 — special-purpose address blocks
- IANA Service Name and Transport Protocol Port Number Registry
- MITRE ATT&CK — technique labels used in alert descriptions (informational)
- Shannon entropy — payload randomness measurement

MITRE ATT&CK is a registered trademark of The MITRE Corporation. Technique
labels are used here for reference only; this project is not affiliated with or
endorsed by MITRE.

## Thanks

To the open-source network-analysis community, whose documentation and tooling
made a fully offline forensics suite possible.
