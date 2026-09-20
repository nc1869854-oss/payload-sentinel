import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Ban,
  Database,
  Gauge,
  GitBranch,
  Package,
  ShieldCheck,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  Cell,
  DataTable,
  KeyValue,
  Meter,
  PageHeader,
  Panel,
  RiskPill,
  Row,
  SeverityPill,
  StatCard,
  StatusDot,
  Tag,
} from "@/components/console";
import {
  FINDINGS,
  FLOWS,
  PROTOCOL_MIX,
  RISK,
  SESSION,
  SEVERITY_COUNTS,
  STATS,
  THROUGHPUT,
  TIMELINE,
  TOP_TALKERS,
  formatBytes,
  formatDuration,
  formatNumber,
} from "@/lib/sample-data";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Session risk score, live throughput, priority detections and the latest investigation events for the active capture session.",
      },
      { property: "og:title", content: "Dashboard — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "One screen answering what is happening on the network, what is unusual, and what to investigate next.",
      },
    ],
  }),
  component: Dashboard,
});

const CHART_TOOLTIP = {
  contentStyle: {
    background: "var(--d4)",
    border: "1px solid var(--b2)",
    borderRadius: 2,
    fontFamily: "var(--font-data)",
    fontSize: 11,
    color: "var(--t1)",
  },
  labelStyle: { color: "var(--t2)" },
} as const;

function Dashboard() {
  const priority = FINDINGS.filter((finding) =>
    ["CRITICAL", "HIGH", "MEDIUM"].includes(finding.severity),
  ).slice(0, 5);

  const riskTone =
    RISK.band === "CRITICAL" || RISK.band === "HIGH" ? "er" : RISK.band === "MEDIUM" ? "wa" : "ok";

  const maxTalker = TOP_TALKERS[0]?.bytes ?? 1;
  const maxProtocol = PROTOCOL_MIX[0]?.value ?? 1;

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Session overview"
        title={SESSION.name}
        description="Everything on this screen was computed on this machine from the captured packets. Nothing was sent anywhere to produce it."
        actions={
          <>
            <Link
              to="/capture"
              className="flex items-center gap-1.5 border border-primary/50 bg-primary/10 px-3 py-1.5 font-data text-xs text-primary transition-colors hover:bg-primary/20"
            >
              <Activity className="size-3.5" /> Open capture
            </Link>
            <Link
              to="/reports"
              className="flex items-center gap-1.5 border border-edge bg-d3 px-3 py-1.5 font-data text-xs text-t2 transition-colors hover:bg-d4 hover:text-t1"
            >
              Build report <ArrowUpRight className="size-3.5" />
            </Link>
          </>
        }
      />

      <div className="grid gap-3 p-4">
        {/* top metrics */}
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <StatCard
            label="Risk score"
            value={RISK.score}
            unit={`/ 100 · ${RISK.band}`}
            tone={riskTone === "er" ? "er" : riskTone === "wa" ? "wa" : "ok"}
            sub={`${SEVERITY_COUNTS.CRITICAL} critical · ${SEVERITY_COUNTS.HIGH} high`}
            icon={<Gauge className="size-4" />}
          />
          <StatCard
            label="Packets captured"
            value={formatNumber(STATS.packets)}
            sub={`${formatDuration(SESSION.durationSeconds)} of capture`}
            icon={<Package className="size-4" />}
          />
          <StatCard
            label="Conversations"
            value={STATS.flows}
            sub={`${STATS.uniqueRemotes} outside addresses`}
            icon={<GitBranch className="size-4" />}
          />
          <StatCard
            label="Traffic volume"
            value={formatBytes(STATS.bytes)}
            sub={`${formatBytes(STATS.payloadBytes)} of payload kept`}
            tone="accent"
            icon={<Database className="size-4" />}
          />
          <StatCard
            label="Name lookups"
            value={formatNumber(STATS.dnsQueries)}
            sub="3 flagged for review"
            icon={<Activity className="size-4" />}
          />
        </div>

        <div className="grid gap-3 xl:grid-cols-3">
          {/* throughput */}
          <Panel
            className="xl:col-span-2"
            title="Throughput"
            hint="KB/s in two-minute buckets"
            actions={
              <span className="flex items-center gap-3 font-data text-[10px] text-t3">
                <span className="flex items-center gap-1">
                  <StatusDot tone="accent" /> OUT
                </span>
                <span className="flex items-center gap-1">
                  <StatusDot tone="ok" /> IN
                </span>
              </span>
            }
          >
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={THROUGHPUT} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                  <defs>
                    <linearGradient id="out" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--accent-blue)" stopOpacity={0.45} />
                      <stop offset="100%" stopColor="var(--accent-blue)" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="in" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--ok)" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="var(--ok)" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--b0)" vertical={false} />
                  <XAxis
                    dataKey="t"
                    tick={{ fill: "var(--t3)", fontSize: 10, fontFamily: "var(--font-data)" }}
                    stroke="var(--b1)"
                    interval={7}
                  />
                  <YAxis
                    tick={{ fill: "var(--t3)", fontSize: 10, fontFamily: "var(--font-data)" }}
                    stroke="var(--b1)"
                  />
                  <Tooltip {...CHART_TOOLTIP} />
                  <Area
                    type="monotone"
                    dataKey="out"
                    stroke="var(--accent-blue)"
                    strokeWidth={1.5}
                    fill="url(#out)"
                  />
                  <Area
                    type="monotone"
                    dataKey="in"
                    stroke="var(--ok)"
                    strokeWidth={1.5}
                    fill="url(#in)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <p className="mt-2 font-data text-[11px] text-t3">
              The raised block from 22:56 onwards is the one-way upload behind detection A-002.
            </p>
          </Panel>

          {/* session facts */}
          <Panel title="Session" hint={SESSION.id}>
            <KeyValue
              rows={[
                ["Analyst", SESSION.analyst],
                ["Source", SESSION.source],
                ["Adapter", SESSION.adapter],
                ["Started", SESSION.startedAt.replace("T", " ")],
                ["Duration", formatDuration(SESSION.durationSeconds)],
                ["Filter", SESSION.filter],
                ["Evidence", `${SESSION.evidenceItems} items · ${SESSION.notes} notes`],
                ["Integrity", SESSION.integrity],
              ]}
            />
            <div className="mt-3 border border-ok/30 bg-ok/5 p-2.5">
              <p className="flex items-center gap-1.5 label-caps text-ok">
                <ShieldCheck className="size-3.5" /> Self-contained
              </p>
              <p className="mt-1 text-xs text-t2">
                Detection, address lookups and reports all run from bundled data on this machine.
              </p>
            </div>
          </Panel>
        </div>

        <div className="grid gap-3 xl:grid-cols-3">
          {/* priority detections */}
          <Panel
            className="xl:col-span-2"
            title="Priority detections"
            hint={`${FINDINGS.length} total`}
            actions={
              <Link to="/alerts" className="font-data text-[11px] text-primary hover:underline">
                View all
              </Link>
            }
            bodyClassName="p-0"
          >
            <DataTable head={["Sev", "Detection", "Technique", "Conf", "Address", "Seen"]}>
              {priority.map((finding) => (
                <Row
                  key={finding.id}
                  tone={
                    finding.severity === "CRITICAL" || finding.severity === "HIGH" ? "er" : "wa"
                  }
                >
                  <Cell>
                    <SeverityPill severity={finding.severity} />
                  </Cell>
                  <Cell className="max-w-[22rem] truncate text-t1">{finding.title}</Cell>
                  <Cell className="hidden max-w-[16rem] truncate md:table-cell">
                    {finding.technique}
                  </Cell>
                  <Cell>{finding.confidence}%</Cell>
                  <Cell>{finding.relatedIp}</Cell>
                  <Cell>{finding.detectedAt}</Cell>
                </Row>
              ))}
            </DataTable>
          </Panel>

          {/* protocol mix */}
          <Panel title="Protocol mix" hint="share of captured packets">
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={PROTOCOL_MIX} margin={{ top: 4, right: 4, bottom: 0, left: -22 }}>
                  <CartesianGrid stroke="var(--b0)" vertical={false} />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: "var(--t3)", fontSize: 10, fontFamily: "var(--font-data)" }}
                    stroke="var(--b1)"
                  />
                  <YAxis
                    tick={{ fill: "var(--t3)", fontSize: 10, fontFamily: "var(--font-data)" }}
                    stroke="var(--b1)"
                  />
                  <Tooltip {...CHART_TOOLTIP} cursor={{ fill: "var(--d4)" }} />
                  <Bar dataKey="value" fill="var(--accent-blue)" radius={[1, 1, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 space-y-1.5">
              {PROTOCOL_MIX.slice(0, 4).map((protocol) => (
                <div key={protocol.name}>
                  <div className="flex items-baseline justify-between font-data text-[11px]">
                    <span className="text-t2">{protocol.name}</span>
                    <span className="text-t3">{protocol.value}</span>
                  </div>
                  <Meter value={protocol.value} max={maxProtocol} />
                </div>
              ))}
            </div>
          </Panel>
        </div>

        <div className="grid gap-3 xl:grid-cols-3">
          {/* top talkers */}
          <Panel title="Busiest outside addresses" hint="by total bytes" bodyClassName="p-0">
            <DataTable head={["Address", "Host", "Volume", "Risk"]}>
              {TOP_TALKERS.map((talker) => (
                <Row key={talker.ip} tone={talker.risk === "CRITICAL" ? "er" : undefined}>
                  <Cell className="text-t1">{talker.ip}</Cell>
                  <Cell className="hidden max-w-[12rem] truncate sm:table-cell">{talker.host}</Cell>
                  <Cell>
                    {formatBytes(talker.bytes)}
                    <Meter
                      value={talker.bytes}
                      max={maxTalker}
                      tone={talker.risk === "CRITICAL" ? "er" : "accent"}
                    />
                  </Cell>
                  <Cell>
                    <RiskPill risk={talker.risk as never} />
                  </Cell>
                </Row>
              ))}
            </DataTable>
          </Panel>

          {/* recent events */}
          <Panel
            className="xl:col-span-2"
            title="Investigation timeline"
            hint="most recent first"
            actions={
              <Link to="/timeline" className="font-data text-[11px] text-primary hover:underline">
                Full timeline
              </Link>
            }
          >
            <ol className="relative space-y-3 border-l border-hair pl-4">
              {[...TIMELINE].reverse().slice(0, 7).map((event) => (
                <li key={`${event.time}-${event.title}`} className="relative">
                  <span
                    className={`absolute -left-[21px] top-1.5 size-2 rounded-full ${
                      event.severity === "CRITICAL" || event.severity === "HIGH"
                        ? "bg-er"
                        : event.severity === "MEDIUM"
                          ? "bg-wa"
                          : "bg-primary"
                    }`}
                  />
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-data text-[11px] text-t3">{event.time}</span>
                    <Tag tone={event.kind === "ALERT" ? "er" : event.kind === "FIREWALL" ? "wa" : "neutral"}>
                      {event.kind}
                    </Tag>
                    <span className="text-sm text-t1">{event.title}</span>
                  </div>
                  <p className="mt-0.5 font-data text-[11px] text-t3">{event.detail}</p>
                </li>
              ))}
            </ol>
          </Panel>
        </div>

        {/* response strip */}
        <div className="grid gap-3 sm:grid-cols-3">
          <Link
            to="/firewall"
            className="group flex items-center gap-3 border border-hair bg-d2 p-3 transition-colors hover:border-wa/50 hover:bg-d3"
          >
            <Ban className="size-5 text-wa" />
            <span className="min-w-0">
              <span className="block text-sm text-t1">Blocking in place</span>
              <span className="block font-data text-[11px] text-t3">
                4 active rules · 1 awaiting approval
              </span>
            </span>
          </Link>
          <Link
            to="/alerts"
            className="group flex items-center gap-3 border border-hair bg-d2 p-3 transition-colors hover:border-er/50 hover:bg-d3"
          >
            <AlertTriangle className="size-5 text-er" />
            <span className="min-w-0">
              <span className="block text-sm text-t1">Needs a decision</span>
              <span className="block font-data text-[11px] text-t3">
                {FINDINGS.filter((finding) => finding.status === "OPEN").length} detections still open
              </span>
            </span>
          </Link>
          <Link
            to="/evidence"
            className="group flex items-center gap-3 border border-hair bg-d2 p-3 transition-colors hover:border-ok/50 hover:bg-d3"
          >
            <ShieldCheck className="size-5 text-ok" />
            <span className="min-w-0">
              <span className="block text-sm text-t1">Evidence sealed</span>
              <span className="block font-data text-[11px] text-t3">
                {SESSION.evidenceItems} items · {SESSION.integrity}
              </span>
            </span>
          </Link>
        </div>

        <p className="font-data text-[11px] text-t3">
          Conversations recorded: {FLOWS.length}. Figures on this page come from one demonstration
          session shipped with the console so every screen has something to show.
        </p>
      </div>
    </div>
  );
}
