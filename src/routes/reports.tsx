import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Download, FileText, Printer } from "lucide-react";

import {
  KeyValue,
  Notice,
  PageHeader,
  Panel,
  SeverityPill,
  StatCard,
  Tag,
} from "@/components/console";
import {
  FINDINGS,
  REPORT_TEMPLATES,
  RISK,
  SESSION,
  STATS,
  formatBytes,
  formatDuration,
  formatNumber,
} from "@/lib/sample-data";
import { APP, OWNER } from "@/lib/owner";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Turn a session into an executive summary, a full technical report, an indicator list or a chain-of-custody document, all generated on this machine.",
      },
      { property: "og:title", content: "Reports — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Four report templates covering management, analysts, blocking teams and legal, exported as PDF, JSON or CSV.",
      },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const [templateId, setTemplateId] = useState(REPORT_TEMPLATES[0]!.id);
  const template = REPORT_TEMPLATES.find((item) => item.id === templateId)!;
  const headline = FINDINGS.filter(
    (finding) => finding.severity === "CRITICAL" || finding.severity === "HIGH",
  );

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Output"
        title="Reports"
        description="Everything the session recorded, written out in the form the reader needs. Generation happens locally — no document ever leaves the machine."
        actions={
          <>
            <button
              type="button"
              className="flex items-center gap-1.5 border border-edge bg-d3 px-3 py-1.5 font-data text-xs text-t2 hover:bg-d4 hover:text-t1"
            >
              <Printer className="size-3.5" /> Preview
            </button>
            <button
              type="button"
              className="flex items-center gap-1.5 border border-primary/50 bg-primary/10 px-3 py-1.5 font-data text-xs text-primary hover:bg-primary/20"
            >
              <Download className="size-3.5" /> Generate {template.format}
            </button>
          </>
        }
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Risk score" value={RISK.score} unit="/ 100" tone={RISK.score >= 60 ? "er" : "wa"} sub={RISK.band} />
          <StatCard label="Findings included" value={FINDINGS.length} sub={`${headline.length} at high or above`} />
          <StatCard label="Packets covered" value={formatNumber(STATS.packets)} sub={formatBytes(STATS.bytes)} />
          <StatCard label="Templates" value={REPORT_TEMPLATES.length} icon={<FileText className="size-4" />} sub="Fixed, auditable layouts" />
        </div>

        <div className="grid gap-3 xl:grid-cols-[1fr_1.5fr]">
          <Panel title="Templates" bodyClassName="p-0">
            <ul>
              {REPORT_TEMPLATES.map((item) => {
                const active = item.id === templateId;
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      onClick={() => setTemplateId(item.id)}
                      className={`w-full border-b border-hair border-l-2 px-3 py-2.5 text-left transition-colors ${
                        active ? "border-l-primary bg-d5/60" : "border-l-transparent hover:bg-d3"
                      }`}
                    >
                      <span className="flex items-center justify-between gap-2">
                        <span className="text-sm text-t1">{item.name}</span>
                        <Tag tone="accent">{item.format}</Tag>
                      </span>
                      <span className="mt-1 block font-data text-[11px] text-t3">{item.audience}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Panel>

          <Panel title="Document preview" hint={template.name} className="bg-d4">
            <div className="border border-hair bg-d0 p-4">
              <p className="label-caps text-primary">{APP.name} · {APP.edition}</p>
              <h3 className="mt-1 text-lg font-semibold text-t1">{template.name}</h3>
              <p className="mt-0.5 font-data text-[11px] text-t3">
                {SESSION.id} · prepared by {OWNER.name} · {OWNER.email}
              </p>

              <div className="mt-4">
                <KeyValue
                  columns={2}
                  rows={[
                    ["Case", SESSION.name],
                    ["Duration", formatDuration(SESSION.durationSeconds)],
                    ["Packets", formatNumber(STATS.packets)],
                    ["Conversations", String(STATS.flows)],
                    ["Risk score", `${RISK.score} / 100 (${RISK.band})`],
                    ["Integrity", SESSION.integrity],
                  ]}
                />
              </div>

              <div className="mt-4">
                <p className="label-caps text-t2">Sections</p>
                <ol className="mt-1.5 grid gap-1 font-data text-[11px] text-t2">
                  {template.sections.map((section, index) => (
                    <li key={section} className="border border-hair bg-d1/60 px-2 py-1">
                      {index + 1}. {section}
                    </li>
                  ))}
                </ol>
              </div>

              <div className="mt-4">
                <p className="label-caps text-t2">Headline findings</p>
                <ul className="mt-1.5 grid gap-1.5">
                  {headline.map((finding) => (
                    <li key={finding.id} className="flex items-start gap-2 border-b border-hair pb-1.5">
                      <SeverityPill severity={finding.severity} />
                      <span className="min-w-0 text-xs text-t2">
                        <span className="text-t1">{finding.title}</span> — {finding.technique}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              <p className="mt-4 border-t border-hair pt-2 font-data text-[10px] text-t3">
                Generated offline by {APP.name} {APP.version}. No external service was contacted while
                producing this document.
              </p>
            </div>
          </Panel>
        </div>

        <Notice tone="accent" title="Write it for the reader">
          The executive summary avoids technical language on purpose — it is meant for whoever decides
          whether to take a machine off the network. The technical report keeps every packet reference.
        </Notice>
      </div>
    </div>
  );
}
