import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Ban, Plus, ShieldCheck } from "lucide-react";

import {
  Cell,
  DataTable,
  Notice,
  PageHeader,
  Panel,
  Row,
  StatCard,
  StatusDot,
  Tag,
} from "@/components/console";
import { FIREWALL_RULES, REMOTE_HOSTS } from "@/lib/sample-data";

export const Route = createFileRoute("/firewall")({
  head: () => ({
    meta: [
      { title: "Firewall control — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Block a hostile address or port straight from a detection, review every rule the suite created, and reverse any of them in one click.",
      },
      { property: "og:title", content: "Firewall control — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Rules created from findings, applied through the operating system's own firewall, each fully reversible.",
      },
    ],
  }),
  component: FirewallPage,
});

function FirewallPage() {
  const [rules, setRules] = useState(FIREWALL_RULES);
  const [target, setTarget] = useState("203.0.113.47");
  const active = rules.filter((rule) => rule.enabled).length;

  const toggle = (name: string) =>
    setRules((current) =>
      current.map((rule) => (rule.name === name ? { ...rule, enabled: !rule.enabled } : rule)),
    );

  const addRule = () => {
    const trimmed = target.trim();
    if (!trimmed) return;
    setRules((current) => [
      {
        name: `PCS-BLOCK-${String(11 + current.length).padStart(4, "0")}`,
        target: trimmed,
        direction: "Outbound",
        action: "Block",
        scope: "All ports",
        createdBy: "Analyst",
        createdAt: new Date().toISOString().slice(11, 19),
        enabled: true,
      },
      ...current,
    ]);
  };

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="Response"
        title="Firewall control"
        description="Stop traffic at the machine itself. Every rule is named, dated, attributed to whatever asked for it, and removable."
        actions={
          <span className="font-data text-xs text-t3">{active} of {rules.length} active</span>
        }
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Rules" value={rules.length} icon={<Ban className="size-4" />} sub="Created by this suite" />
          <StatCard label="Active" value={active} tone="ok" sub="Currently enforced" icon={<ShieldCheck className="size-4" />} />
          <StatCard
            label="Blocked addresses"
            value={rules.filter((rule) => rule.action === "Block").length}
            tone="er"
            sub="Outbound and inbound"
          />
          <StatCard label="Applied by" value="System firewall" sub="No third-party driver needed" />
        </div>

        <Panel title="Block something now">
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              spellCheck={false}
              placeholder="Address, range or domain"
              className="min-w-[16rem] flex-1 border border-edge bg-d4 px-2 py-1.5 font-data text-xs text-t1 outline-none focus:border-focus"
            />
            <button
              type="button"
              onClick={addRule}
              className="flex items-center gap-1.5 border border-er/50 bg-er/10 px-3 py-1.5 font-data text-xs text-er hover:bg-er/20"
            >
              <Plus className="size-3.5" /> Block outbound
            </button>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {REMOTE_HOSTS.filter((host) => host.risk === "CRITICAL" || host.risk === "HIGH").map(
              (host) => (
                <button
                  key={host.ip}
                  type="button"
                  onClick={() => setTarget(host.ip)}
                  className="border border-er/40 bg-er/5 px-2 py-1 font-data text-[11px] text-er hover:bg-er/15"
                >
                  {host.ip} · {host.risk}
                </button>
              ),
            )}
          </div>
        </Panel>

        <Panel title="Rules" hint="toggle to enable or disable" bodyClassName="p-0">
          <DataTable head={["State", "Name", "Target", "Direction", "Action", "Scope", "Created by", "Time", ""]}>
            {rules.map((rule) => (
              <Row key={rule.name} tone={rule.action === "Block" && rule.enabled ? "er" : undefined}>
                <Cell>
                  <StatusDot tone={rule.enabled ? "ok" : "idle"} />
                </Cell>
                <Cell className="text-t1">{rule.name}</Cell>
                <Cell>{rule.target}</Cell>
                <Cell>{rule.direction}</Cell>
                <Cell>
                  <Tag tone={rule.action === "Block" ? "er" : "ok"}>{rule.action}</Tag>
                </Cell>
                <Cell>{rule.scope}</Cell>
                <Cell>{rule.createdBy}</Cell>
                <Cell>{rule.createdAt}</Cell>
                <Cell>
                  <button
                    type="button"
                    onClick={() => toggle(rule.name)}
                    className="border border-edge bg-d3 px-2 py-0.5 font-data text-[11px] text-t2 hover:bg-d4 hover:text-t1"
                  >
                    {rule.enabled ? "Disable" : "Enable"}
                  </button>
                </Cell>
              </Row>
            ))}
          </DataTable>
        </Panel>

        <Notice tone="wa" title="Blocking can break things">
          A block applies to the whole machine. If you block a range that also carries something you
          rely on, that will stop working too. Every rule here can be disabled again from this table.
        </Notice>
      </div>
    </div>
  );
}
