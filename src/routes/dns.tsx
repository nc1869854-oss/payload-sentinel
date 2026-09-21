import { createFileRoute } from "@tanstack/react-router";
import { Globe, ShieldQuestion } from "lucide-react";

import {
  Cell,
  DataTable,
  Notice,
  PageHeader,
  Panel,
  Row,
  StatCard,
  Tag,
} from "@/components/console";
import { DNS_RECORDS, STATS, formatNumber } from "@/lib/sample-data";

export const Route = createFileRoute("/dns")({
  head: () => ({
    meta: [
      { title: "Name lookups — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Every domain this machine asked about, how often, what answered, and which lookups carry the long random labels that indicate smuggled data.",
      },
      { property: "og:title", content: "Name lookups — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Domain lookup history with verdicts, answer records and tunnelling indicators, resolved from offline tables only.",
      },
    ],
  }),
  component: DnsPage,
});

const VERDICT_TONE = {
  OK: "ok",
  SUSPICIOUS: "wa",
  BLOCKED: "er",
} as const;

function DnsPage() {
  const suspicious = DNS_RECORDS.filter((record) => record.verdict !== "OK");
  const longest = DNS_RECORDS.reduce((best, record) =>
    record.query.length > best.query.length ? record : best,
  );

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Analysis"
        title="Name lookups"
        description="Before a machine connects anywhere it usually asks for the address first. That question list is one of the most revealing records in a capture."
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Lookups"
            value={formatNumber(STATS.dnsQueries)}
            sub={`${DNS_RECORDS.length} distinct names`}
            icon={<Globe className="size-4" />}
          />
          <StatCard
            label="Flagged"
            value={suspicious.length}
            tone={suspicious.length > 0 ? "wa" : "ok"}
            sub="Suspicious or blocked"
          />
          <StatCard
            label="Longest name"
            value={`${longest.query.length} ch`}
            tone="er"
            sub={longest.query.slice(0, 26)}
            icon={<ShieldQuestion className="size-4" />}
          />
          <StatCard
            label="Resolvers used"
            value={new Set(DNS_RECORDS.map((record) => record.resolver)).size}
            sub="1.1.1.1 and the local gateway"
          />
        </div>

        <Panel title="Lookup history" hint="grouped by name" bodyClassName="p-0">
          <DataTable head={["Time", "Name asked", "Type", "Answer", "Resolver", "Count", "Verdict", "Note"]}>
            {DNS_RECORDS.map((record) => (
              <Row
                key={record.query}
                tone={
                  record.verdict === "BLOCKED" ? "er" : record.verdict === "SUSPICIOUS" ? "wa" : undefined
                }
              >
                <Cell>{record.time}</Cell>
                <Cell className="max-w-[20rem] truncate text-t1">{record.query}</Cell>
                <Cell>{record.type}</Cell>
                <Cell className="max-w-[16rem] truncate">{record.answer}</Cell>
                <Cell>{record.resolver}</Cell>
                <Cell>{formatNumber(record.count)}</Cell>
                <Cell>
                  <Tag tone={VERDICT_TONE[record.verdict]}>{record.verdict}</Tag>
                </Cell>
                <Cell className="max-w-[22rem] truncate text-t3">{record.note}</Cell>
              </Row>
            ))}
          </DataTable>
        </Panel>

        <div className="grid gap-3 lg:grid-cols-2">
          <Notice tone="wa" title="What a tunnelling lookup looks like">
            A normal name is short and repeats often: <span className="font-data">www.google.com</span>.
            A tunnel hides data inside the name itself, so you see very long, never-repeating labels
            under one domain — exactly the pattern under hosted-metrics.io in this session.
          </Notice>
          <Notice tone="accent" title="Everything resolved offline">
            Names are matched against tables bundled with the program. No lookup service is contacted,
            so investigating a hostile domain never tips off whoever owns it.
          </Notice>
        </div>
      </div>
    </div>
  );
}
