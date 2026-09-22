import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Clock } from "lucide-react";

import { Notice, PageHeader, Panel, SeverityPill, StatCard } from "@/components/console";
import { SESSION, TIMELINE, formatDuration, type TimelineEvent } from "@/lib/sample-data";

export const Route = createFileRoute("/timeline")({
  head: () => ({
    meta: [
      { title: "Session timeline — Payload Capture Suite" },
      {
        name: "description",
        content:
          "The whole session in order: capture start, detections, evidence taken, firewall actions and analyst notes, with the integrity check at the end.",
      },
      { property: "og:title", content: "Session timeline — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "A single ordered account of what happened during the capture, suitable for pasting straight into an incident write-up.",
      },
    ],
  }),
  component: TimelinePage,
});

const KINDS: Array<TimelineEvent["kind"] | "ALL"> = [
  "ALL",
  "CAPTURE",
  "ALERT",
  "FLOW",
  "DNS",
  "EVIDENCE",
  "FIREWALL",
  "NOTE",
];

const KIND_COLOUR: Record<TimelineEvent["kind"], string> = {
  CAPTURE: "border-primary/60 bg-primary/15 text-primary",
  ALERT: "border-er/60 bg-er/15 text-er",
  FLOW: "border-in/60 bg-in/15 text-in",
  DNS: "border-wa/60 bg-wa/15 text-wa",
  EVIDENCE: "border-ok/60 bg-ok/15 text-ok",
  FIREWALL: "border-edge bg-d5 text-t1",
  NOTE: "border-edge bg-d3 text-t2",
};

function TimelinePage() {
  const [kind, setKind] = useState<TimelineEvent["kind"] | "ALL">("ALL");
  const visible = kind === "ALL" ? TIMELINE : TIMELINE.filter((event) => event.kind === kind);
  const alerts = TIMELINE.filter((event) => event.kind === "ALERT").length;

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Reconstruction"
        title="Session timeline"
        description="Everything that happened, in the order it happened. This is the version of the story you hand to somebody else."
        actions={
          <div className="flex flex-wrap items-center gap-1">
            {KINDS.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setKind(item)}
                className={`border px-2 py-1 font-data text-[11px] transition-colors ${
                  kind === item
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
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Events recorded" value={TIMELINE.length} icon={<Clock className="size-4" />} />
          <StatCard label="Detections raised" value={alerts} tone="er" sub="Across the session" />
          <StatCard
            label="Session length"
            value={formatDuration(SESSION.durationSeconds)}
            sub={`Started ${SESSION.startedAt.replace("T", " ")}`}
          />
          <StatCard label="Integrity" value="VERIFIED" tone="ok" sub={SESSION.integrity} />
        </div>

        <Panel title="Ordered account" hint={`${visible.length} events`}>
          <ol className="relative ml-2 border-l border-edge pl-6">
            {visible.map((event, index) => (
              <li key={`${event.time}-${index}`} className="relative pb-5 last:pb-0">
                <span
                  className={`absolute -left-[31px] top-1 size-2.5 rounded-full border-2 ${
                    event.kind === "ALERT" ? "border-er bg-er/40" : "border-primary bg-primary/30"
                  }`}
                />
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-data text-xs text-t1">{event.time}</span>
                  <span
                    className={`border px-1.5 py-0.5 font-data text-[10px] tracking-wider ${KIND_COLOUR[event.kind]}`}
                  >
                    {event.kind}
                  </span>
                  <SeverityPill severity={event.severity} />
                </div>
                <p className="mt-1.5 text-sm text-t1">{event.title}</p>
                <p className="mt-0.5 font-data text-[11px] text-t3">{event.detail}</p>
              </li>
            ))}
          </ol>
        </Panel>

        <Notice tone="accent" title="Times are local to the capturing machine">
          All timestamps come from the clock on the machine that captured the traffic. If you compare
          this against another system's logs, check both clocks first.
        </Notice>
      </div>
    </div>
  );
}
