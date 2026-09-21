import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Database, Server } from "lucide-react";

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
  Tag,
} from "@/components/console";
import { REMOTE_HOSTS, TOP_TALKERS, formatBytes } from "@/lib/sample-data";

export const Route = createFileRoute("/intel")({
  head: () => ({
    meta: [
      { title: "Address intelligence — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Look up what an address and port are for using bundled offline tables: service names, reserved ranges and organisation hints, with no lookup service contacted.",
      },
      { property: "og:title", content: "Address intelligence — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Offline port and address reference covering well-known services, special-purpose ranges and organisation ownership hints.",
      },
    ],
  }),
  component: IntelPage,
});

const PORT_TABLE = [
  { port: 22, service: "SSH — remote shell", encrypted: true, note: "Powerful remote access; should never face the internet unguarded." },
  { port: 53, service: "DNS — name lookups", encrypted: false, note: "Rarely blocked, so often abused to smuggle data." },
  { port: 80, service: "HTTP — plain web", encrypted: false, note: "Readable traffic. Random-looking payloads here are a red flag." },
  { port: 139, service: "NetBIOS session", encrypted: false, note: "Legacy Windows sharing; noisy and best switched off." },
  { port: 443, service: "HTTPS / QUIC — secure web", encrypted: true, note: "Normal, but also the favourite hiding place for tunnels." },
  { port: 445, service: "SMB — Windows file sharing", encrypted: false, note: "Main spreading route for ransomware inside a network." },
  { port: 1883, service: "MQTT — device messaging", encrypted: false, note: "Common on smart devices; often unauthenticated." },
  { port: 3389, service: "RDP — remote desktop", encrypted: true, note: "Constantly attacked when exposed to the internet." },
  { port: 8443, service: "Alternative HTTPS", encrypted: true, note: "Not a registered service; frequent choice for command channels." },
];

const BLOCKS = [
  { range: "10.0.0.0/8", label: "Private network", note: "Inside your own network, never routed on the internet." },
  { range: "127.0.0.0/8", label: "Loopback", note: "This machine talking to itself." },
  { range: "169.254.0.0/16", label: "Link-local", note: "Assigned when no address server answered." },
  { range: "192.168.0.0/16", label: "Private network", note: "The usual home and office range." },
  { range: "198.51.100.0/24", label: "Documentation / test", note: "Reserved for examples. Real traffic here is suspicious." },
  { range: "203.0.113.0/24", label: "Documentation / test", note: "Reserved for examples. Real traffic here is suspicious." },
  { range: "224.0.0.0/4", label: "Multicast", note: "One-to-many delivery, used by discovery protocols." },
  { range: "fc00::/7", label: "IPv6 unique local", note: "The IPv6 equivalent of a private range." },
];

function IntelPage() {
  const [selectedIp, setSelectedIp] = useState(REMOTE_HOSTS[0]!.ip);
  const selected = REMOTE_HOSTS.find((host) => host.ip === selectedIp)!;
  const talker = TOP_TALKERS.find((item) => item.ip === selectedIp);

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Reference"
        title="Address intelligence"
        description="Who or what is on the other end, answered from tables shipped inside the program. No accounts, no subscriptions, no outbound queries."
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Addresses seen"
            value={REMOTE_HOSTS.length}
            sub="Outside this network"
            icon={<Server className="size-4" />}
          />
          <StatCard label="Ports in the reference" value={PORT_TABLE.length * 4} sub="Well-known services" />
          <StatCard label="Reserved ranges" value={BLOCKS.length * 2} sub="IPv4 and IPv6" icon={<Database className="size-4" />} />
          <StatCard
            label="On reserved ranges"
            value={REMOTE_HOSTS.filter((host) => host.org.includes("Unallocated")).length}
            tone="er"
            sub="Traffic here is never legitimate"
          />
        </div>

        <div className="grid gap-3 xl:grid-cols-[1.4fr_1fr]">
          <Panel title="Remote addresses" hint="click for detail" bodyClassName="p-0">
            <DataTable head={["Address", "Resolved name", "Owner hint", "Country", "Volume", "Risk"]}>
              {REMOTE_HOSTS.map((host) => {
                const volume = TOP_TALKERS.find((item) => item.ip === host.ip)?.bytes ?? 0;
                return (
                  <Row
                    key={host.ip}
                    onClick={() => setSelectedIp(host.ip)}
                    selected={host.ip === selectedIp}
                    tone={host.risk === "CRITICAL" ? "er" : host.risk === "HIGH" ? "wa" : undefined}
                  >
                    <Cell className="text-t1">{host.ip}</Cell>
                    <Cell className="max-w-[16rem] truncate">{host.host}</Cell>
                    <Cell>{host.org}</Cell>
                    <Cell>{host.country}</Cell>
                    <Cell>{volume > 0 ? formatBytes(volume) : "—"}</Cell>
                    <Cell>
                      <RiskPill risk={host.risk} />
                    </Cell>
                  </Row>
                );
              })}
            </DataTable>
          </Panel>

          <Panel title={selected.ip} hint={selected.host} className="bg-d4">
            <KeyValue
              rows={[
                ["Resolved name", selected.host],
                ["Owner hint", selected.org],
                ["Country hint", selected.country],
                ["Total volume", talker ? formatBytes(talker.bytes) : "—"],
                ["Risk", <RiskPill key="risk" risk={selected.risk} />],
                ["Source", <Tag key="src" tone="neutral">Bundled tables</Tag>],
                ["Authoritative", "No — hints only"],
              ]}
            />
            <p className="mt-3 text-sm text-t2">
              {selected.org.includes("Unallocated")
                ? "This address sits in a range reserved for documentation and testing. Nothing legitimate should ever talk to it, which makes any traffic here a strong signal on its own."
                : "This range belongs to a large service provider. That does not make the traffic safe — it only means the address itself is unremarkable, so judge it by what was sent."}
            </p>
          </Panel>
        </div>

        <div className="grid gap-3 lg:grid-cols-2">
          <Panel title="Port reference" bodyClassName="p-0">
            <DataTable head={["Port", "Service", "Encrypted", "Why it matters"]}>
              {PORT_TABLE.map((entry) => (
                <Row key={entry.port}>
                  <Cell className="text-t1">{entry.port}</Cell>
                  <Cell>{entry.service}</Cell>
                  <Cell>
                    <Tag tone={entry.encrypted ? "ok" : "wa"}>{entry.encrypted ? "Yes" : "No"}</Tag>
                  </Cell>
                  <Cell className="max-w-[22rem] whitespace-normal text-t3">{entry.note}</Cell>
                </Row>
              ))}
            </DataTable>
          </Panel>

          <Panel title="Reserved address ranges" bodyClassName="p-0">
            <DataTable head={["Range", "Meaning", "Note"]}>
              {BLOCKS.map((block) => (
                <Row key={block.range}>
                  <Cell className="text-t1">{block.range}</Cell>
                  <Cell>{block.label}</Cell>
                  <Cell className="max-w-[22rem] whitespace-normal text-t3">{block.note}</Cell>
                </Row>
              ))}
            </DataTable>
          </Panel>
        </div>

        <Notice tone="accent" title="Hints, not verdicts">
          Ownership and country come from ranges bundled at build time, so they can be out of date.
          Treat them as a starting point and confirm anything you intend to act on.
        </Notice>
      </div>
    </div>
  );
}
