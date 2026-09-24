import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  BookOpen,
  FileText,
  Gavel,
  Info,
  ScrollText,
  ShieldCheck,
  Heart,
} from "lucide-react";

import { Notice, PageHeader, Panel } from "@/components/console";
import { COPYRIGHT, OWNER } from "@/lib/owner";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/legal")({
  head: () => ({
    meta: [
      { title: "Legal — Payload Capture Suite" },
      {
        name: "description",
        content:
          "License, privacy policy, disclaimer, do's and don'ts, terms of use, legal compliance and credits for Payload Capture Suite.",
      },
      { property: "og:title", content: "Legal — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "All legal documents for Payload Capture Suite in one place. General templates — read before publishing.",
      },
    ],
  }),
  component: LegalPage,
});

/* ── document definitions ────────────────────────────────────────────────── */

type LegalDoc = {
  key: string;
  title: string;
  icon: typeof FileText;
  lastUpdated?: string;
  sections: LegalSection[];
};

type LegalSection = {
  heading: string;
  body?: string;
  list?: string[];
  table?: string[][];
};

const DOCS: LegalDoc[] = [
  {
    key: "license",
    title: "License",
    icon: ScrollText,
    sections: [
      {
        heading: "Payload Capture Suite 2.0.0 (Final Edition)",
        body: `Copyright © 2026 ${OWNER.name}. All rights reserved.\nContact: ${OWNER.email} — Social: ${OWNER.handle}`,
      },
      { heading: "1. Grant", body: "You are granted a personal, non-exclusive, non-transferable licence to install and use this software for lawful network analysis, education, research and authorised security testing." },
      {
        heading: "2. Permitted use",
        list: [
          "Install and run the software on machines you own or administer.",
          "Analyse traffic on networks you own, or on networks where you hold documented written authorisation to monitor.",
          "Use generated reports internally, and in legal or disciplinary proceedings where the underlying capture was lawfully obtained.",
          "Study and modify the source for your own private use.",
        ],
      },
      {
        heading: "3. Restrictions",
        list: [
          "Sell, sublicense, rent or redistribute the software, modified or otherwise, without written permission from the copyright holder.",
          "Remove or obscure the ownership, copyright or attribution notices.",
          "Use the software to intercept traffic you are not authorised to monitor.",
          "Present the software's automated findings as forensic proof without independent verification by a qualified analyst.",
        ],
      },
      { heading: "4. Third-party components", body: "This software uses independently licensed open-source components. Their licences apply to those components and are listed in the Credits document." },
      { heading: "5. No warranty", body: "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT." },
      { heading: "6. Limitation of liability", body: "IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES, DATA LOSS, SERVICE INTERRUPTION OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING IN OR IN CONNECTION WITH THE SOFTWARE OR ITS USE." },
      { heading: "7. Termination", body: "This licence terminates automatically if you breach any term. On termination you must stop using the software and delete all copies." },
      { heading: "8. Governing law", body: "This licence is governed by the laws of India, without regard to conflict-of-law rules." },
    ],
  },
  {
    key: "privacy",
    title: "Privacy Policy",
    icon: ShieldCheck,
    lastUpdated: "2026",
    sections: [
      {
        heading: "The short version",
        body: "Payload Capture Suite runs entirely on your computer. It has no accounts, no API keys, no analytics and no telemetry. Nothing you capture is ever sent anywhere by this software.",
      },
      {
        heading: "1. What the software stores",
        body: "All data stays on your machine, in the application folder:",
        table: [
          ["data/evidence.db", "Sessions, packets, flows, alerts, notes, audit log"],
          ["logs/", "Application log for troubleshooting"],
          ["exports/", "Reports and exports you generate"],
          ["config/settings.json", "Your preferences"],
        ],
      },
      {
        heading: "2. What the software sends out",
        body: "Nothing. There are no outbound connections, update checks, crash reports, usage statistics or cloud lookups. Threat rules and address intelligence ship inside the application as local data files.",
      },
      {
        heading: "3. Your responsibilities as the operator",
        list: [
          "Capture only on networks you own or are authorised in writing to monitor.",
          "Tell people who use those networks that monitoring takes place, where the law requires it.",
          "Keep evidence files encrypted at rest and restricted to those who need them.",
          "Delete captures once the investigation that justified them is closed.",
        ],
      },
      { heading: "4. Retention and deletion", body: "The software never deletes your data automatically. Removing a session from the Sessions screen deletes its packets, flows, alerts and notes from the local database. Deleting the data/ folder removes everything." },
      { heading: "5. Children", body: "This is a professional security tool and is not intended for use by children." },
      { heading: "6. Changes", body: "Changes to this policy are published with new versions of the software. The \"last updated\" date above marks the current revision." },
      { heading: "7. Contact", body: `Questions about this policy: ${OWNER.email}` },
    ],
  },
  {
    key: "disclaimer",
    title: "Disclaimer",
    icon: Info,
    sections: [
      { heading: "1. Purpose", body: "Payload Capture Suite is a defensive analysis and educational tool. It is built for network owners, administrators, students and authorised security professionals who need to understand traffic on networks they are responsible for." },
      { heading: "2. Authorisation is your responsibility", body: "Intercepting network traffic without authorisation is a criminal offence in most countries. Running this software on a network you do not own or administer, without documented permission, may expose you to criminal and civil liability. The author provides the tool; you carry sole responsibility for how it is used." },
      {
        heading: "3. Automated findings are hints, not verdicts",
        body: "Alerts produced by the detection rules are based on statistical heuristics. They can be wrong in both directions:",
        list: [
          "False positives — legitimate software such as updaters, backups and monitoring agents can look exactly like beaconing or scanning.",
          "False negatives — a careful attacker can stay under every threshold in this tool.",
        ],
      },
      { heading: "4. Not a replacement for professional security tooling", body: "This suite does not replace an intrusion detection system, an endpoint protection product, a SIEM, or a professional incident-response engagement. It has no signature feed, no deep packet inspection of encrypted traffic, and no ability to decrypt TLS." },
      { heading: "5. Evidence handling", body: "Hashing and the audit log are provided to support chain of custody, but admissibility depends entirely on your own procedures, authorisation and local law. Consult qualified counsel before relying on output in proceedings." },
      { heading: "6. Firewall controls", body: "The blocking features change your operating system firewall and require administrator rights. An incorrect rule can cut off legitimate services, including remote access to the machine itself. Review every rule before applying it." },
      { heading: "7. No warranty", body: "The software is provided \"as is\" without warranty of any kind. The author is not liable for any loss, damage, downtime, data loss or legal consequence arising from its use." },
    ],
  },
  {
    key: "dos-and-donts",
    title: "Do's and Don'ts",
    icon: BookOpen,
    sections: [
      {
        heading: "Do",
        list: [
          "Get authorisation in writing before capturing on any network that is not your own, and keep it with the case file.",
          "Run as administrator when you need live capture or firewall control; both require elevated rights.",
          "Install the capture driver (Npcap on Windows) before expecting live traffic. Everything else works without it.",
          "Name your sessions after the case or incident so reports are traceable months later.",
          "Verify every alert in the packet and flow views before acting on it.",
          "Hash and export evidence as soon as a capture is finished, and store the export on separate media.",
          "Annotate what you find with notes as you go; they appear in reports and save hours later.",
          "Prefer PCAP export when handing work to another analyst; it keeps the original bytes intact.",
          "Delete captures once the investigation that justified them is closed.",
          "Keep the tool offline; it needs no internet and is safer without it.",
        ],
      },
      {
        heading: "Don't",
        list: [
          "Capture on public, shared, employer or customer networks without explicit authority. This is the single fastest way to commit a crime with a defensive tool.",
          "Treat an alert as proof. Heuristics flag patterns, not intent.",
          "Block addresses on production networks without change approval; a wrong rule can take services down.",
          "Store evidence databases unencrypted on shared drives; captures can contain credentials and private messages.",
          "Edit data/evidence.db by hand. Manual edits destroy the integrity of the audit trail and the evidence hashes.",
          "Share raw captures publicly, including in bug reports or forums; redact first.",
          "Run capture indefinitely on a busy interface without a packet limit; the database and disk will fill.",
          "Rely on this tool alone for monitoring a production environment.",
          "Assume encrypted traffic is safe or that plaintext traffic is malicious; both need context.",
          "Redistribute the software without permission from the owner.",
        ],
      },
      {
        heading: "Quick pre-capture checklist",
        list: [
          "Authorisation documented and in reach.",
          "Correct interface selected and packet limit set.",
          "Session named after the case.",
          "Running with administrator rights.",
          "Storage location has free space and is encrypted.",
        ],
      },
    ],
  },
  {
    key: "terms",
    title: "Terms of Use",
    icon: FileText,
    sections: [
      { heading: "1. Eligibility", body: "You must be legally capable of entering into this agreement and must have the authority to monitor any network on which you use the software." },
      {
        heading: "2. Acceptable use",
        body: "You will use the software only for lawful purposes, including:",
        list: [
          "analysing traffic on networks you own or administer;",
          "authorised security assessment with documented written permission;",
          "education, research and training in isolated or consenting environments;",
          "incident response on systems you are responsible for.",
        ],
      },
      {
        heading: "3. Prohibited use",
        body: "You will not use the software to:",
        list: [
          "intercept communications without lawful authority;",
          "capture credentials, messages or personal data belonging to others for personal gain, harassment, blackmail or stalking;",
          "attack, disrupt, scan or map networks you do not control;",
          "build or operate a commercial monitoring service without written permission from the owner;",
          "circumvent, disable or misrepresent the licence and attribution notices.",
        ],
      },
      { heading: "4. Your data", body: "The software stores everything locally and transmits nothing. You are the controller of all captured data and responsible for its lawful handling. See the Privacy Policy." },
      { heading: "5. Intellectual property", body: "The software, its interface, its documentation and its detection rules remain the property of the owner. Third-party components remain the property of their respective authors under their own licences." },
      { heading: "6. No warranty and limitation of liability", body: "The software is provided \"as is\" with no warranty. To the maximum extent permitted by law, the owner is not liable for any direct, indirect, incidental or consequential loss arising from its use, including data loss, downtime, missed detections or false accusations based on its output." },
      { heading: "7. Indemnity", body: "You agree to indemnify the owner against any claim arising from your use of the software, including unauthorised monitoring." },
      { heading: "8. Suspension and termination", body: "Your right to use the software ends immediately upon breach of these terms or of the licence." },
      { heading: "9. Changes", body: "These terms may be revised with new releases. Continued use after a release means acceptance of the revised terms." },
      { heading: "10. Governing law", body: "These terms are governed by the laws of India." },
    ],
  },
  {
    key: "compliance",
    title: "Legal and Compliance",
    icon: Gavel,
    sections: [
      {
        heading: "1. The core rule",
        body: "Capture traffic only where you have a lawful basis. In practice that means one of:",
        list: [
          "you own the network and the endpoints on it;",
          "you administer the network on behalf of its owner, within your job scope;",
          "you hold signed authorisation for a defined scope, target list and time window;",
          "every participant in the communication has consented;",
          "you are acting under a lawful order or warrant.",
        ],
      },
      {
        heading: "2. Frequently relevant law",
        table: [
          ["India", "Information Technology Act 2000 (ss. 43, 66, 69), Telegraph Act 1885, DPDP Act 2023"],
          ["European Union", "GDPR, ePrivacy Directive, national interception statutes"],
          ["United Kingdom", "Computer Misuse Act 1990, Investigatory Powers Act 2016, UK GDPR"],
          ["United States", "Wiretap Act (18 U.S.C. § 2511), Computer Fraud and Abuse Act, state consent laws"],
          ["Canada", "Criminal Code s. 184, PIPEDA"],
          ["Australia", "Telecommunications (Interception and Access) Act 1979, Privacy Act 1988"],
        ],
      },
      { heading: "3. Workplace monitoring", body: "Where an employer monitors staff traffic, most regimes additionally require a written, published monitoring policy; notice to employees before monitoring begins; proportionality; a defined retention period and secure storage; and special care around health, union, legal and personal correspondence." },
      { heading: "4. Handling captured personal data", body: "Captured packets are personal data when they can be linked to a person. Treat them accordingly: minimise what you collect, restrict access, encrypt at rest, log who opened what, and delete on schedule. The audit log in this software supports the access-logging part, not the rest." },
      {
        heading: "5. Evidence and chain of custody",
        body: "For output to be useful in a proceeding, keep a record of:",
        list: [
          "who authorised the capture, and the scope of that authority;",
          "which machine and interface captured it, and when;",
          "the SHA-256 hash of every exported file, recorded at export time;",
          "every person who has since held a copy;",
          "the software version that produced the report.",
        ],
      },
      { heading: "6. Security testing", body: "If you use the scanning-related features against a third party, confirm the engagement has a signed scope, a named technical contact, an agreed test window and a documented rollback plan." },
      { heading: "7. Export and cryptography rules", body: "Some jurisdictions restrict possession or export of network-interception software. Confirm your local position before carrying the tool across borders." },
      { heading: "8. When in doubt", body: "Stop, document what you have, and take qualified legal advice before you continue. An unlawful capture cannot be made lawful afterwards." },
    ],
  },
  {
    key: "credits",
    title: "Credits",
    icon: Heart,
    sections: [
      {
        heading: "Author",
        body: `${OWNER.name} — owner, architect and lead developer\nEmail: ${OWNER.email}\nSocial: ${OWNER.handle}`,
      },
      {
        heading: "Third-party components",
        table: [
          ["Python", "Runtime", "PSF License"],
          ["Tkinter / Tcl-Tk", "Desktop interface", "Tcl/Tk BSD-style licence"],
          ["Scapy", "Packet capture, parsing and PCAP handling", "GPL-2.0"],
          ["ReportLab", "PDF report generation", "BSD-3-Clause"],
          ["SQLite", "Embedded evidence database", "Public domain"],
          ["Npcap (Windows, optional)", "Packet capture driver", "Npcap licence — install separately"],
          ["PyInstaller (build only)", "Windows executable packaging", "GPL-2.0 with exception"],
          ["NSIS (build only)", "Windows installer", "zlib/libpng licence"],
        ],
      },
      {
        heading: "Standards and references",
        list: [
          "RFC 1918 / RFC 6890 — special-purpose address blocks",
          "IANA Service Name and Transport Protocol Port Number Registry",
          "MITRE ATT&CK — technique labels used in alert descriptions (informational)",
          "Shannon entropy — payload randomness measurement",
        ],
      },
      { heading: "Note on Scapy", body: "Scapy is licensed under the GPL-2.0. If you distribute a build that bundles Scapy, your distribution must comply with that licence." },
      { heading: "MITRE ATT&CK", body: "MITRE ATT&CK is a registered trademark of The MITRE Corporation. Technique labels are used here for reference only; this project is not affiliated with or endorsed by MITRE." },
      { heading: "Thanks", body: "To the open-source network-analysis community, whose documentation and tooling made a fully offline forensics suite possible." },
    ],
  },
];

/* ── component ──────────────────────────────────────────────────────────── */

function LegalPage() {
  const [activeKey, setActiveKey] = useState(DOCS[0].key);
  const active = DOCS.find((doc) => doc.key === activeKey) ?? DOCS[0];

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="System"
        title="Legal"
        description="All the documents that govern use of the suite. These are general templates — read them before publishing."
      />

      <div className="grid gap-3 p-4 lg:grid-cols-[260px_1fr]">
        {/* ── document list ──────────────────────────────────────────────── */}
        <nav className="flex flex-col gap-1">
          {DOCS.map((doc) => {
            const Icon = doc.icon;
            const activeDoc = doc.key === activeKey;
            return (
              <button
                key={doc.key}
                type="button"
                onClick={() => setActiveKey(doc.key)}
                className={cn(
                  "flex items-center gap-2.5 border-l-2 px-3 py-2 text-left text-sm transition-colors",
                  activeDoc
                    ? "border-l-primary bg-primary/10 text-t1"
                    : "border-l-transparent text-t2 hover:bg-d3 hover:text-t1",
                )}
              >
                <Icon className={cn("size-4 shrink-0", activeDoc ? "text-primary" : "text-t3")} />
                <span className="truncate">{doc.title}</span>
              </button>
            );
          })}

          <div className="mt-2 border-t border-hair pt-2">
            <Notice tone="wa" title="General templates">
              <p className="text-xs text-t2">
                These documents are general templates and not legal advice. Have them reviewed by a
                qualified professional before relying on them commercially.
              </p>
            </Notice>
          </div>
        </nav>

        {/* ── document reader ────────────────────────────────────────────── */}
        <Panel title={active.title} hint={active.lastUpdated ? `Last updated ${active.lastUpdated}` : undefined}>
          <article>
            {active.sections.map((section, index) => (
              <section key={index} className="mb-5 last:mb-0">
                <h3 className="text-sm font-semibold text-t1">{section.heading}</h3>
                {section.body && (
                  <p className="mt-1.5 whitespace-pre-line text-sm text-t2">{section.body}</p>
                )}
                {section.list && (
                  <ul className="mt-2 space-y-1.5">
                    {section.list.map((item, i) => (
                      <li key={i} className="flex gap-2 text-sm text-t2">
                        <span className="mt-1.5 size-1 shrink-0 rounded-full bg-primary/60" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {section.table && (
                  <div className="mt-2 overflow-x-auto">
                    <table className="w-full border-collapse text-left text-sm">
                      <tbody>
                        {section.table.map((row, i) => (
                          <tr key={i} className="border-b border-hair">
                            {row.map((cell, j) => (
                              <td
                                key={j}
                                className={cn(
                                  "whitespace-nowrap px-2.5 py-1.5 font-data text-xs",
                                  j === 0 ? "text-t1" : "text-t2",
                                )}
                              >
                                {cell}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            ))}

            <div className="mt-6 border-t border-hair pt-3">
              <p className="font-data text-[11px] text-t3">{COPYRIGHT}</p>
            </div>
          </article>
        </Panel>
      </div>
    </div>
  );
}
