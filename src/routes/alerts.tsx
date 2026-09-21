import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Bell, ShieldAlert, Target } from "lucide-react";

import {
  KeyValue,
  Meter,
  Notice,
  PageHeader,
  Panel,
  SeverityPill,
  StatCard,
  Tag,
} from "@/components/console";
import { FINDINGS, RISK, SEVERITY_COUNTS, type Severity } from "@/lib/sample-data";

export const Route = createFileRoute("/alerts")({
  head: () => ({
    meta: [
      { title: "Detections — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Sixteen offline detections explain what they found in plain language, with the evidence behind each result and a recommended next step.",
      },
      { property: "og:title", content: "Detections — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Beaconing, exfiltration, scanning, tunnelling and off-hours activity, each with a confidence score and supporting evidence.",
      },
    ],
  }),
  component: AlertsPage,
});

const FILTERS: Array<Severity | "ALL"> = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function AlertsPage() {
  const [filter, setFilter] = useState<Severity | "ALL">("ALL");
  const [selectedId, setSelectedId] = useState(FINDINGS[0]!.id);

  const visible = useMemo(
    () => (filter === "ALL" ? FINDINGS : FINDINGS.filter((item) => item.severity === filter)),
    [filter],
  );

  const selected = visible.find((item) => item.id === selectedId) ?? visible[0] ?? FINDINGS[0]!;

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Analysis"
        title="Detections"
        description="Each detection says what it saw, why that matters and what to do next. Nothing here is sent anywhere — the rules run entirely on this machine."
        actions={
          <div className="flex flex-wrap items-center gap-1">
            {FILTERS.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setFilter(item)}
                className={`border px-2 py-1 font-data text-[11px] transition-colors ${
                  filter === item
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-edge bg-d3 text-t2 hover:bg-d4 hover:text-t1"
                }`}
              >
                {item}
              </button>
            ))}
          </div>
        }
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <StatCard
            label="Risk score"
            value={RISK.score}
            unit="/ 100"
            tone={RISK.score >= 75 ? "er" : RISK.score >= 40 ? "wa" : "ok"}
            sub={`Band: ${RISK.band}`}
            icon={<ShieldAlert className="size-4" />}
          />
          <StatCard label="Critical" value={SEVERITY_COUNTS.CRITICAL} tone="er" sub="Act now" />
          <StatCard label="High" value={SEVERITY_COUNTS.HIGH} tone="er" sub="Act today" />
          <StatCard label="Medium" value={SEVERITY_COUNTS.MEDIUM} tone="wa" sub="Investigate" />
          <StatCard
            label="Low and informational"
            value={SEVERITY_COUNTS.LOW + SEVERITY_COUNTS.INFO}
            tone="ok"
            sub="For the record"
            icon={<Bell className="size-4" />}
          />
        </div>

        <div className="grid gap-3 xl:grid-cols-[1fr_1.4fr]">
          <Panel title="Findings" hint={`${visible.length} shown`} bodyClassName="p-0">
            <ul className="max-h-[38rem] overflow-y-auto">
              {visible.map((finding) => {
                const active = finding.id === selected.id;
                return (
                  <li key={finding.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(finding.id)}
                      className={`w-full border-b border-hair border-l-2 px-3 py-2.5 text-left transition-colors ${
                        active
                          ? "border-l-primary bg-d5/60"
                          : "border-l-transparent hover:bg-d3"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <SeverityPill severity={finding.severity} />
                        <span className="font-data text-[11px] text-t3">{finding.id}</span>
                        <span className="ml-auto font-data text-[11px] text-t3">
                          {finding.detectedAt}
                        </span>
                      </span>
                      <span className="mt-1.5 block text-sm text-t1">{finding.title}</span>
                      <span className="mt-1 block font-data text-[11px] text-t3">
                        {finding.technique}
                      </span>
                      <span className="mt-2 flex items-center gap-2">
                        <span className="w-24">
                          <Meter
                            value={finding.confidence}
                            max={100}
                            tone={finding.confidence >= 80 ? "er" : finding.confidence >= 60 ? "wa" : "accent"}
                          />
                        </span>
                        <span className="font-data text-[11px] text-t3">
                          {finding.confidence}% confidence
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Panel>

          <div className="flex flex-col gap-3">
            <Panel
              title={selected.id}
              hint={selected.technique}
              className="bg-d4"
              actions={<SeverityPill severity={selected.severity} />}
            >
              <h3 className="text-lg font-semibold text-t1">{selected.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-t2">{selected.description}</p>

              <div className="mt-4">
                <p className="label-caps text-t2">Evidence</p>
                <ul className="mt-2 grid gap-1">
                  {selected.evidence.map((line) => (
                    <li
                      key={line}
                      className="flex items-start gap-2 border border-hair bg-d0 px-2 py-1.5 font-data text-[11px] text-t2"
                    >
                      <Target className="mt-0.5 size-3 shrink-0 text-primary" />
                      {line}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="mt-4">
                <KeyValue
                  columns={2}
                  rows={[
                    ["Detected at", selected.detectedAt],
                    ["Confidence", `${selected.confidence}%`],
                    ["Related address", selected.relatedIp],
                    ["Related conversation", selected.relatedFlow],
                    ["Status", <Tag key="status" tone={selected.status === "OPEN" ? "wa" : "accent"}>{selected.status}</Tag>],
                    ["Severity", <SeverityPill key="sev" severity={selected.severity} />],
                  ]}
                />
              </div>
            </Panel>

            <Notice
              tone={selected.severity === "CRITICAL" || selected.severity === "HIGH" ? "er" : "accent"}
              title="Recommended next step"
            >
              {selected.recommendation}
            </Notice>

            <Panel title="Response actions" bodyClassName="flex flex-wrap gap-2 p-3">
              <button
                type="button"
                className="border border-er/50 bg-er/10 px-3 py-1.5 font-data text-xs text-er hover:bg-er/20"
              >
                Block {selected.relatedIp}
              </button>
              <button
                type="button"
                className="border border-edge bg-d3 px-3 py-1.5 font-data text-xs text-t2 hover:bg-d4 hover:text-t1"
              >
                Attach evidence to case
              </button>
              <button
                type="button"
                className="border border-edge bg-d3 px-3 py-1.5 font-data text-xs text-t2 hover:bg-d4 hover:text-t1"
              >
                Mark as triaged
              </button>
              <button
                type="button"
                className="border border-primary/50 bg-primary/10 px-3 py-1.5 font-data text-xs text-primary hover:bg-primary/20"
              >
                Add to report
              </button>
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}
