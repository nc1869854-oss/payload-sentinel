import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Binary, Search, SlidersHorizontal } from "lucide-react";

import {
  Cell,
  DataTable,
  KeyValue,
  PageHeader,
  Panel,
  RiskPill,
  Row,
  Tag,
} from "@/components/console";
import { PACKETS, formatNumber, type Risk } from "@/lib/sample-data";

export const Route = createFileRoute("/packets")({
  head: () => ({
    meta: [
      { title: "Packet inspector — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Browse every captured packet, filter by protocol, risk or address, and read the raw payload side by side with the decoded protocol stack.",
      },
      { property: "og:title", content: "Packet inspector — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "A searchable packet table with a hex and ASCII payload view, protocol stack breakdown and randomness measurement.",
      },
    ],
  }),
  component: PacketsPage,
});

const PROTOCOL_FILTERS = ["ALL", "TCP", "TLS", "UDP", "DNS", "HTTP", "QUIC", "ICMP", "ARP"] as const;
const RISK_FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

function PacketsPage() {
  const [protocol, setProtocol] = useState<(typeof PROTOCOL_FILTERS)[number]>("ALL");
  const [risk, setRisk] = useState<(typeof RISK_FILTERS)[number]>("ALL");
  const [query, setQuery] = useState("");
  const [selectedNumber, setSelectedNumber] = useState(PACKETS[0]!.number);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return PACKETS.filter((packet) => {
      if (protocol !== "ALL" && packet.protocol !== protocol) return false;
      if (risk !== "ALL" && packet.risk !== (risk as Risk)) return false;
      if (!needle) return true;
      return (
        packet.srcIp.includes(needle) ||
        packet.dstIp.includes(needle) ||
        packet.summary.toLowerCase().includes(needle) ||
        String(packet.srcPort ?? "").includes(needle) ||
        String(packet.dstPort ?? "").includes(needle)
      );
    }).slice(0, 200);
  }, [protocol, risk, query]);

  const selected =
    filtered.find((packet) => packet.number === selectedNumber) ?? filtered[0] ?? PACKETS[0]!;

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Inspection"
        title="Packet inspector"
        description="Every packet the session captured, with its payload. Select a row to read the decoded stack and the raw bytes."
        actions={
          <span className="font-data text-xs text-t3">
            {formatNumber(filtered.length)} shown of {formatNumber(PACKETS.length)}
          </span>
        }
      />

      <div className="grid gap-3 p-4">
        <Panel title="Filters" bodyClassName="p-3">
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex min-w-[16rem] flex-1 items-center gap-2 border border-edge bg-d4 px-2">
              <Search className="size-3.5 text-t3" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search address, port or summary"
                className="w-full bg-transparent py-1.5 font-data text-xs text-t1 outline-none"
              />
            </label>

            <div className="flex items-center gap-1">
              <SlidersHorizontal className="size-3.5 text-t3" />
              {PROTOCOL_FILTERS.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setProtocol(item)}
                  className={`border px-2 py-1 font-data text-[11px] transition-colors ${
                    protocol === item
                      ? "border-primary/50 bg-primary/10 text-primary"
                      : "border-edge bg-d3 text-t2 hover:bg-d4 hover:text-t1"
                  }`}
                >
                  {item}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1">
              {RISK_FILTERS.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setRisk(item)}
                  className={`border px-2 py-1 font-data text-[11px] transition-colors ${
                    risk === item
                      ? "border-focus bg-d5 text-t1"
                      : "border-edge bg-d3 text-t2 hover:bg-d4 hover:text-t1"
                  }`}
                >
                  {item}
                </button>
              ))}
            </div>
          </div>
        </Panel>

        <div className="grid gap-3 xl:grid-cols-[1.6fr_1fr]">
          <Panel title="Packets" hint="click a row to inspect" bodyClassName="p-0">
            <div className="max-h-[32rem] overflow-y-auto">
              <DataTable head={["#", "Time", "Dir", "Proto", "Source", "Destination", "Len", "Risk"]}>
                {filtered.map((packet) => (
                  <Row
                    key={packet.number}
                    onClick={() => setSelectedNumber(packet.number)}
                    selected={packet.number === selected.number}
                    tone={
                      packet.risk === "CRITICAL" || packet.risk === "HIGH"
                        ? "er"
                        : packet.risk === "MEDIUM"
                          ? "wa"
                          : undefined
                    }
                  >
                    <Cell className="text-t3">{packet.number}</Cell>
                    <Cell>{packet.time}</Cell>
                    <Cell>
                      <Tag
                        tone={
                          packet.direction === "OUTGOING"
                            ? "accent"
                            : packet.direction === "INCOMING"
                              ? "in"
                              : "neutral"
                        }
                      >
                        {packet.direction.slice(0, 3)}
                      </Tag>
                    </Cell>
                    <Cell className="text-t1">{packet.protocol}</Cell>
                    <Cell>
                      {packet.srcIp}
                      {packet.srcPort ? `:${packet.srcPort}` : ""}
                    </Cell>
                    <Cell>
                      {packet.dstIp}
                      {packet.dstPort ? `:${packet.dstPort}` : ""}
                    </Cell>
                    <Cell>{packet.size}</Cell>
                    <Cell>
                      <RiskPill risk={packet.risk} />
                    </Cell>
                  </Row>
                ))}
              </DataTable>
              {filtered.length === 0 ? (
                <p className="p-6 text-center font-data text-xs text-t3">
                  No packets match these filters.
                </p>
              ) : null}
            </div>
          </Panel>

          {/* inspector — elevated surface */}
          <div className="flex flex-col gap-3">
            <Panel title={`Packet ${selected.number}`} hint={selected.stack} className="bg-d4">
              <KeyValue
                columns={1}
                rows={[
                  ["Captured at", selected.time],
                  ["Direction", selected.direction],
                  ["Protocol", selected.protocol],
                  [
                    "Source",
                    `${selected.srcIp}${selected.srcPort ? `:${selected.srcPort}` : ""}`,
                  ],
                  [
                    "Destination",
                    `${selected.dstIp}${selected.dstPort ? `:${selected.dstPort}` : ""}`,
                  ],
                  ["Frame length", `${selected.size} bytes`],
                  ["Payload", `${selected.payloadSize} bytes`],
                  ["Randomness", `${selected.entropy} / 8.0`],
                  ["Conversation", selected.flowId],
                  ["Risk", <RiskPill key="risk" risk={selected.risk} />],
                ]}
              />
              <p className="mt-3 text-xs text-t2">{selected.summary}</p>
              {selected.entropy > 7.3 ? (
                <p className="mt-2 border border-wa/30 bg-wa/5 p-2 text-xs text-wa">
                  This payload is as random as encrypted data. On a port that should carry readable
                  text, that is worth a closer look.
                </p>
              ) : null}
            </Panel>

            <Panel
              title="Payload"
              hint="hex and ASCII"
              className="bg-d4"
              actions={<Binary className="size-3.5 text-t3" />}
            >
              <pre className="max-h-64 overflow-auto whitespace-pre border border-hair bg-d0 p-2.5 font-data text-[11px] leading-relaxed text-t2">
                {selected.payloadSize > 0
                  ? selected.payloadPreview
                  : "No payload — this packet carries protocol headers only."}
              </pre>
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}
