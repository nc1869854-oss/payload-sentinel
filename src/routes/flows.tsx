import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { ArrowDownLeft, ArrowUpRight, GitBranch } from "lucide-react";

import {
  Cell,
  DataTable,
  KeyValue,
  Meter,
  Notice,
  PageHeader,
  Panel,
  RiskPill,
  Row,
  StatCard,
  Tag,
} from "@/components/console";
import { FLOWS, formatBytes, formatNumber } from "@/lib/sample-data";

export const Route = createFileRoute("/flows")({
  head: () => ({
    meta: [
      { title: "Conversations — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Every conversation the machine held, grouped by address and port, with volume sent against volume received so one-sided transfers stand out.",
      },
      { property: "og:title", content: "Conversations — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Grouped connection records with direction, duration, byte balance and risk for each remote address.",
      },
    ],
  }),
  component: FlowsPage,
});

type SortKey = "bytes" | "packets" | "risk";

const RISK_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 } as const;

function FlowsPage() {
  const [sortKey, setSortKey] = useState<SortKey>("bytes");
  const [selectedId, setSelectedId] = useState(FLOWS[0]!.id);

  const sorted = useMemo(() => {
    const list = [...FLOWS];
    if (sortKey === "bytes") {
      list.sort((a, b) => b.bytesOut + b.bytesIn - (a.bytesOut + a.bytesIn));
    } else if (sortKey === "packets") {
      list.sort((a, b) => b.packets - a.packets);
    } else {
      list.sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk]);
    }
    return list;
  }, [sortKey]);

  const selected = sorted.find((flow) => flow.id === selectedId) ?? sorted[0]!;
  const maxVolume = sorted[0] ? sorted[0].bytesOut + sorted[0].bytesIn : 1;
  const totalOut = FLOWS.reduce((total, flow) => total + flow.bytesOut, 0);
  const totalIn = FLOWS.reduce((total, flow) => total + flow.bytesIn, 0);
  const oneSided = FLOWS.filter((flow) => flow.bytesOut > flow.bytesIn * 8).length;

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Correlation"
        title="Conversations"
        description="Packets grouped into the conversations they belong to. The byte balance column is where data theft usually shows itself first."
        actions={
          <div className="flex items-center gap-1">
            {(["bytes", "packets", "risk"] as SortKey[]).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => setSortKey(key)}
                className={`border px-2 py-1 font-data text-[11px] capitalize transition-colors ${
                  sortKey === key
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-edge bg-d3 text-t2 hover:bg-d4 hover:text-t1"
                }`}
              >
                Sort by {key}
              </button>
            ))}
          </div>
        }
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Conversations"
            value={FLOWS.length}
            sub={`${new Set(FLOWS.map((flow) => flow.remoteIp)).size} distinct remote addresses`}
            icon={<GitBranch className="size-4" />}
          />
          <StatCard
            label="Sent"
            value={formatBytes(totalOut)}
            tone="accent"
            sub="From this machine outwards"
            icon={<ArrowUpRight className="size-4" />}
          />
          <StatCard
            label="Received"
            value={formatBytes(totalIn)}
            sub="Into this machine"
            icon={<ArrowDownLeft className="size-4" />}
          />
          <StatCard
            label="Heavily one-sided"
            value={oneSided}
            tone={oneSided > 0 ? "er" : "ok"}
            sub="Sent more than 8× what came back"
          />
        </div>

        <div className="grid gap-3 xl:grid-cols-[1.7fr_1fr]">
          <Panel title="Conversation records" hint="click a row for detail" bodyClassName="p-0">
            <div className="max-h-[34rem] overflow-y-auto">
              <DataTable
                head={["ID", "Proto", "Remote address", "Host", "Pkts", "Out", "In", "Balance", "State", "Risk"]}
              >
                {sorted.map((flow) => {
                  const volume = flow.bytesOut + flow.bytesIn;
                  const lopsided = flow.bytesOut > flow.bytesIn * 8;
                  return (
                    <Row
                      key={flow.id}
                      onClick={() => setSelectedId(flow.id)}
                      selected={flow.id === selected.id}
                      tone={
                        flow.risk === "CRITICAL" || flow.risk === "HIGH"
                          ? "er"
                          : flow.risk === "MEDIUM"
                            ? "wa"
                            : undefined
                      }
                    >
                      <Cell className="text-t3">{flow.id}</Cell>
                      <Cell className="text-t1">{flow.protocol}</Cell>
                      <Cell>
                        {flow.remoteIp}:{flow.remotePort}
                      </Cell>
                      <Cell className="hidden max-w-[13rem] truncate lg:table-cell">
                        {flow.remoteHost}
                      </Cell>
                      <Cell>{formatNumber(flow.packets)}</Cell>
                      <Cell className={lopsided ? "text-er" : undefined}>
                        {formatBytes(flow.bytesOut)}
                      </Cell>
                      <Cell>{formatBytes(flow.bytesIn)}</Cell>
                      <Cell className="w-24">
                        <Meter value={volume} max={maxVolume} tone={lopsided ? "er" : "accent"} />
                      </Cell>
                      <Cell className="hidden sm:table-cell">{flow.state}</Cell>
                      <Cell>
                        <RiskPill risk={flow.risk} />
                      </Cell>
                    </Row>
                  );
                })}
              </DataTable>
            </div>
          </Panel>

          <div className="flex flex-col gap-3">
            <Panel title={`Conversation ${selected.id}`} hint={selected.remoteHost} className="bg-d4">
              <KeyValue
                rows={[
                  ["Protocol", selected.protocol],
                  ["Local", `${selected.localIp}:${selected.localPort}`],
                  ["Remote", `${selected.remoteIp}:${selected.remotePort}`],
                  ["Resolved name", selected.remoteHost],
                  ["Packets", formatNumber(selected.packets)],
                  ["Sent", formatBytes(selected.bytesOut)],
                  ["Received", formatBytes(selected.bytesIn)],
                  [
                    "Ratio out:in",
                    `${(selected.bytesOut / Math.max(1, selected.bytesIn)).toFixed(1)} : 1`,
                  ],
                  ["First seen", selected.firstSeen],
                  ["Last seen", selected.lastSeen],
                  ["Direction", <Tag key="dir" tone="accent">{selected.direction}</Tag>],
                  ["State", selected.state],
                  ["Risk", <RiskPill key="risk" risk={selected.risk} />],
                ]}
              />
            </Panel>

            {selected.bytesOut > selected.bytesIn * 8 ? (
              <Notice tone="er" title="One-sided transfer">
                This conversation sent far more than it received. Normal browsing is the other way
                round, so check what was uploaded and to whom before clearing it.
              </Notice>
            ) : (
              <Notice tone="accent" title="Balance looks ordinary">
                Sent and received volumes are within the range expected for regular use of this
                protocol.
              </Notice>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
