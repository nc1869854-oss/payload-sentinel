import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { CircleStop, Filter, Pause, Play, Radio, RotateCcw, Save } from "lucide-react";

import {
  Cell,
  DataTable,
  KeyValue,
  Notice,
  PageHeader,
  Panel,
  RiskPill,
  Row,
  StatCard,
  StatusDot,
  Tag,
} from "@/components/console";
import { PACKETS, SESSION, STATS, formatBytes, formatNumber } from "@/lib/sample-data";

export const Route = createFileRoute("/capture")({
  head: () => ({
    meta: [
      { title: "Live capture — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Start, pause and filter a live packet capture, watch packets arrive in real time and attach anything interesting straight to the case file.",
      },
      { property: "og:title", content: "Live capture — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Adapter selection, capture filters and a live packet stream, all handled on the machine doing the capture.",
      },
    ],
  }),
  component: CapturePage;
});

const ADAPTERS = [
  { name: "Intel(R) Wi-Fi 6E AX211 160MHz", kind: "Wireless", address: "192.168.1.114", state: "Up" },
  { name: "Realtek PCIe GbE Family Controller", kind: "Ethernet", address: "—", state: "Down" },
  { name: "Loopback Pseudo-Interface 1", kind: "Loopback", address: "127.0.0.1", state: "Up" },
  { name: "WireGuard Tunnel", kind: "Virtual", address: "10.6.0.2", state: "Up" },
];

const PRESETS = [
  { label: "Everything", filter: "" },
  { label: "Quiet the noise", filter: "not (port 137 or port 138)" },
  { label: "Web only", filter: "tcp port 80 or tcp port 443" },
  { label: "Name lookups", filter: "udp port 53" },
  { label: "File sharing", filter: "tcp port 445 or tcp port 139" },
  { label: "Leaving this machine", filter: "src host 192.168.1.114" },
];

function CapturePage() {
  const [running, setRunning] = useState(true);
  const [cursor, setCursor] = useState(24);
  const [filter, setFilter] = useState<string>(SESSION.filter);
  const [adapter, setAdapter] = useState(ADAPTERS[0]!.name);

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => {
      setCursor((current) => (current + 1) % PACKETS.length);
    }, 900);
    return () => window.clearInterval(timer);
  }, [running]);

  const stream = useMemo(() => {
    const start = Math.max(0, cursor - 17);
    return PACKETS.slice(start, cursor + 1).reverse();
  }, [cursor]);

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Acquisition"
        title="Live capture"
        description="Choose an adapter, narrow the traffic with a filter, then watch packets arrive. Capture only on networks you own or are authorised to monitor."
        actions={
          <>
            <button
              type="button"
              onClick={() => setRunning((value) => !value)}
              className={`flex items-center gap-1.5 border px-3 py-1.5 font-data text-xs transition-colors ${
                running
                  ? "border-wa/50 bg-wa/10 text-wa hover:bg-wa/20"
                  : "border-ok/50 bg-ok/10 text-ok hover:bg-ok/20"
              }`}
            >
              {running ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
              {running ? "Pause" : "Resume"}
            </button>
            <button
              type="button"
              onClick={() => setCursor(24)}
              className="flex items-center gap-1.5 border border-edge bg-d3 px-3 py-1.5 font-data text-xs text-t2 transition-colors hover:bg-d4 hover:text-t1"
            >
              <RotateCcw className="size-3.5" /> Restart view
            </button>
            <button
              type="button"
              className="flex items-center gap-1.5 border border-er/50 bg-er/10 px-3 py-1.5 font-data text-xs text-er transition-colors hover:bg-er/20"
            >
              <CircleStop className="size-3.5" /> Stop and seal
            </button>
          </>
        }
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="State"
            value={running ? "CAPTURING" : "PAUSED"}
            tone={running ? "ok" : "wa"}
            sub={`Buffer ${formatNumber(cursor + 1)} / ${formatNumber(PACKETS.length)} shown`}
            icon={<Radio className="size-4" />}
          />
          <StatCard
            label="Packets this session"
            value={formatNumber(STATS.packets)}
            sub="Written to the case database"
          />
          <StatCard
            label="Payload retained"
            value={formatBytes(STATS.payloadBytes)}
            sub="Trimmed to 1,460 bytes per packet"
            tone="accent"
          />
          <StatCard
            label="Dropped by driver"
            value="0"
            sub="No buffer pressure"
            tone="ok"
          />
        </div>

        <div className="grid gap-3 xl:grid-cols-4">
          <Panel title="Adapter" className="xl:col-span-1" bodyClassName="p-0">
            <ul>
              {ADAPTERS.map((item) => {
                const active = item.name === adapter;
                return (
                  <li key={item.name}>
                    <button
                      type="button"
                      onClick={() => setAdapter(item.name)}
                      disabled={item.state === "Down"}
                      className={`flex w-full flex-col items-start gap-1 border-b border-hair border-l-2 px-3 py-2 text-left transition-colors disabled:opacity-40 ${
                        active
                          ? "border-l-primary bg-primary/10"
                          : "border-l-transparent hover:bg-d3"
                      }`}
                    >
                      <span className="flex w-full items-center gap-2">
                        <StatusDot tone={item.state === "Up" ? "ok" : "idle"} pulse={active && running} />
                        <span className="truncate text-xs text-t1">{item.name}</span>
                      </span>
                      <span className="font-data text-[10px] text-t3">
                        {item.kind} · {item.address} · {item.state}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Panel>

          <Panel title="Capture filter" className="xl:col-span-3">
            <div className="flex items-center gap-2">
              <Filter className="size-4 shrink-0 text-t3" />
              <input
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                spellCheck={false}
                placeholder="e.g. tcp port 443 and not host 192.168.1.1"
                className="min-w-0 flex-1 border border-edge bg-d4 px-2 py-1.5 font-data text-xs text-t1 outline-none focus:border-focus"
              />
              <button
                type="button"
                className="border border-primary/50 bg-primary/10 px-3 py-1.5 font-data text-xs text-primary hover:bg-primary/20"
              >
                Apply
              </button>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {PRESETS.map((preset) => (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => setFilter(preset.filter)}
                  className={`border px-2 py-1 font-data text-[11px] transition-colors ${
                    preset.filter === filter
                      ? "border-primary/50 bg-primary/10 text-primary"
                      : "border-edge bg-d3 text-t2 hover:bg-d4 hover:text-t1"
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <KeyValue
                rows={[
                  ["Snap length", "1518 bytes"],
                  ["Payload kept", "1460 bytes"],
                  ["Promiscuous", "Enabled"],
                  ["Ring buffer", "256 MB"],
                ]}
              />
              <KeyValue
                rows={[
                  ["Case", SESSION.id],
                  ["Autosave", "Every 30 seconds"],
                  ["Hashing", "SHA-256 on write"],
                  ["Name resolution", "Offline tables only"],
                ]}
              />
            </div>
          </Panel>
        </div>

        <Panel
          title="Live stream"
          hint={running ? "newest at the top" : "paused"}
          className={running ? "sweep-line" : undefined}
          actions={
            <button
              type="button"
              className="flex items-center gap-1.5 border border-edge bg-d3 px-2 py-1 font-data text-[11px] text-t2 hover:bg-d4 hover:text-t1"
            >
              <Save className="size-3" /> Attach selection to case
            </button>
          }
          bodyClassName="p-0"
        >
          <DataTable
            head={["#", "Time", "Dir", "Protocol", "Source", "Destination", "Bytes", "Payload", "Risk", "Summary"]}
          >
            {stream.map((packet) => (
              <Row
                key={packet.number}
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
                  <Tag tone={packet.direction === "OUTGOING" ? "accent" : packet.direction === "INCOMING" ? "in" : "neutral"}>
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
                <Cell>{packet.payloadSize}</Cell>
                <Cell>
                  <RiskPill risk={packet.risk} />
                </Cell>
                <Cell className="max-w-[18rem] truncate text-t3">{packet.summary}</Cell>
              </Row>
            ))}
          </DataTable>
        </Panel>

        <Notice tone="wa" title="Before you capture">
          Recording other people's traffic without permission is illegal in most countries. Use this
          on your own machines, your own network, or where you have written authorisation.
        </Notice>
      </div>
    </div>
  );
}
