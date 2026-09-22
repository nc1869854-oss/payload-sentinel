import { createFileRoute } from "@tanstack/react-router";
import { FileCheck2, Fingerprint, Folder, Lock } from "lucide-react";

import {
  Cell,
  DataTable,
  KeyValue,
  Notice,
  PageHeader,
  Panel,
  Row,
  StatCard,
  Tag,
} from "@/components/console";
import { EVIDENCE, SESSION, formatDuration, formatNumber } from "@/lib/sample-data";
import { OWNER } from "@/lib/owner";

export const Route = createFileRoute("/evidence")({
  head: () => ({
    meta: [
      { title: "Evidence locker — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Attached packets, conversation records, notes and capture slices, each fingerprinted when stored so you can prove nothing changed afterwards.",
      },
      { property: "og:title", content: "Evidence locker — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Chain-of-custody records with SHA-256 fingerprints, timestamps and the analyst who attached each item.",
      },
    ],
  }),
  component: EvidencePage,
});

const CUSTODY = [
  { time: "22:04:11", actor: OWNER.name, action: "Case opened", detail: `Session ${SESSION.id} created` },
  { time: "22:26:03", actor: OWNER.name, action: "Item attached", detail: "E-001 · 84 packets hashed on write" },
  { time: "22:42:02", actor: OWNER.name, action: "Item attached", detail: "E-002 · conversation record F-001" },
  { time: "22:55:36", actor: OWNER.name, action: "Note recorded", detail: "E-004 · owner interview" },
  { time: "23:15:44", actor: OWNER.name, action: "Item attached", detail: "E-003 · capture slice, 2,411 packets" },
  { time: "23:31:07", actor: OWNER.name, action: "Bundle sealed", detail: "23 items · ledger written to case database" },
  { time: "23:59:12", actor: "Suite", action: "Integrity verified", detail: "0 mismatches across 4,284 packets" },
];

function EvidencePage() {
  const totalItems = EVIDENCE.reduce((total, item) => total + item.items, 0);

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Custody"
        title="Evidence locker"
        description="Anything you attach is copied into the case database and fingerprinted immediately, so it can be shown later to be exactly what was collected."
        actions={
          <button
            type="button"
            className="flex items-center gap-1.5 border border-primary/50 bg-primary/10 px-3 py-1.5 font-data text-xs text-primary hover:bg-primary/20"
          >
            <Lock className="size-3.5" /> Seal bundle
          </button>
        }
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Evidence items" value={SESSION.evidenceItems} icon={<Folder className="size-4" />} sub={`${EVIDENCE.length} groups`} />
          <StatCard label="Records inside" value={formatNumber(totalItems)} sub="Packets, flows and notes" />
          <StatCard label="Fingerprints" value="SHA-256" tone="accent" sub="Written at collection time" icon={<Fingerprint className="size-4" />} />
          <StatCard label="Verification" value="PASSED" tone="ok" sub="0 mismatches" icon={<FileCheck2 className="size-4" />} />
        </div>

        <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr]">
          <Panel title="Attached items" bodyClassName="p-0">
            <DataTable head={["ID", "Kind", "Label", "Records", "Fingerprint", "Added", "By"]}>
              {EVIDENCE.map((item) => (
                <Row key={item.id}>
                  <Cell className="text-t3">{item.id}</Cell>
                  <Cell>
                    <Tag tone="neutral">{item.kind}</Tag>
                  </Cell>
                  <Cell className="max-w-[20rem] truncate text-t1">{item.label}</Cell>
                  <Cell>{formatNumber(item.items)}</Cell>
                  <Cell>{item.hash}</Cell>
                  <Cell>{item.addedAt}</Cell>
                  <Cell>{item.addedBy}</Cell>
                </Row>
              ))}
            </DataTable>
          </Panel>

          <Panel title="Case record" className="bg-d4">
            <KeyValue
              rows={[
                ["Case", SESSION.id],
                ["Name", SESSION.name],
                ["Analyst", SESSION.analyst],
                ["Source", SESSION.source],
                ["Adapter", SESSION.adapter],
                ["Started", SESSION.startedAt.replace("T", " ")],
                ["Duration", formatDuration(SESSION.durationSeconds)],
                ["Capture filter", SESSION.filter || "none"],
                ["Notes", String(SESSION.notes)],
                ["Integrity", SESSION.integrity],
              ]}
            />
          </Panel>
        </div>

        <Panel title="Chain of custody" hint="append-only" bodyClassName="p-0">
          <DataTable head={["Time", "Who", "Action", "Detail"]}>
            {CUSTODY.map((entry) => (
              <Row key={`${entry.time}-${entry.action}`}>
                <Cell>{entry.time}</Cell>
                <Cell className="text-t1">{entry.actor}</Cell>
                <Cell>{entry.action}</Cell>
                <Cell className="max-w-[26rem] truncate text-t3">{entry.detail}</Cell>
              </Row>
            ))}
          </DataTable>
        </Panel>

        <Notice tone="accent" title="Why fingerprints matter">
          A fingerprint is a short code calculated from the data itself. Change one byte and the code
          changes completely, so anyone can check later that the evidence is untouched — without
          needing to trust you or this program.
        </Notice>
      </div>
    </div>
  );
}
