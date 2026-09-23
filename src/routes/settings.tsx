import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Cpu, Sliders } from "lucide-react";

import {
  KeyValue,
  Notice,
  PageHeader,
  Panel,
  StatCard,
  Tag,
} from "@/components/console";
import { APP, OFFLINE_NOTICE, OWNER } from "@/lib/owner";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — Payload Capture Suite" },
      {
        name: "description",
        content:
          "Tune the detection thresholds, storage limits and quiet hours the suite uses, and confirm that nothing is configured to reach the internet.",
      },
      { property: "og:title", content: "Settings — Payload Capture Suite" },
      {
        property: "og:description",
        content:
          "Detection tuning, retention limits and a plain statement of what the program does and does not send anywhere.",
      },
    ],
  }),
  component: SettingsPage,
});

type Threshold = {
  key: string;
  label: string;
  explain: string;
  value: number;
  min: number;
  max: number;
  step: number;
  unit: string;
};

const INITIAL: Threshold[] = [
  { key: "beacon", label: "Beacon minimum contacts", explain: "How many evenly-spaced contacts before it counts as a heartbeat.", value: 6, min: 3, max: 30, step: 1, unit: "contacts" },
  { key: "scan", label: "Port scan threshold", explain: "Distinct ports tried on one machine before it looks like a scan.", value: 15, min: 5, max: 80, step: 1, unit: "ports" },
  { key: "sweep", label: "Host sweep threshold", explain: "Distinct machines contacted before it looks like a sweep.", value: 20, min: 5, max: 100, step: 1, unit: "hosts" },
  { key: "exfil", label: "Upload alarm", explain: "Total bytes sent to one address before an upload alarm is raised.", value: 5, min: 1, max: 100, step: 1, unit: "MB" },
  { key: "entropy", label: "Randomness limit", explain: "Above this, a payload is treated as encrypted or compressed.", value: 7.2, min: 6, max: 8, step: 0.1, unit: "of 8.0" },
  { key: "dns", label: "Long-name limit", explain: "Name length that suggests data hidden inside a lookup.", value: 45, min: 20, max: 120, step: 1, unit: "characters" },
];

function SettingsPage() {
  const [thresholds, setThresholds] = useState(INITIAL);
  const [retention, setRetention] = useState(30);
  const [quietFrom, setQuietFrom] = useState("22:00");
  const [quietTo, setQuietTo] = useState("06:00");

  const update = (key: string, value: number) =>
    setThresholds((current) =>
      current.map((item) => (item.key === key ? { ...item, value } : item)),
    );

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="System"
        title="Settings"
        description="Detection is a balance: sensitive settings catch more and cry wolf more. These are the numbers every rule reads."
        actions={
          <button
            type="button"
            onClick={() => setThresholds(INITIAL)}
            className="border border-edge bg-d3 px-3 py-1.5 font-data text-xs text-t2 hover:bg-d4 hover:text-t1"
          >
            Restore defaults
          </button>
        }
      />

      <div className="grid gap-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Detection rules" value={16} sub="All running locally" icon={<Sliders className="size-4" />} />
          <StatCard label="Outbound connections" value="0" tone="ok" sub="By design" />
          <StatCard label="Keys or accounts needed" value="None" tone="ok" sub="Nothing to configure" />
          <StatCard label="Version" value={APP.version} sub={APP.edition} icon={<Cpu className="size-4" />} />
        </div>

        <Panel title="Detection thresholds">
          <div className="grid gap-4 lg:grid-cols-2">
            {thresholds.map((item) => (
              <div key={item.key} className="border border-hair bg-d3/60 p-3">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-sm text-t1">{item.label}</span>
                  <span className="font-data text-xs text-primary">
                    {item.value} {item.unit}
                  </span>
                </div>
                <p className="mt-1 text-xs text-t2">{item.explain}</p>
                <input
                  type="range"
                  min={item.min}
                  max={item.max}
                  step={item.step}
                  value={item.value}
                  onChange={(event) => update(item.key, Number(event.target.value))}
                  className="mt-2.5 w-full accent-primary"
                />
              </div>
            ))}
          </div>
        </Panel>

        <div className="grid gap-3 lg:grid-cols-2">
          <Panel title="Storage and retention">
            <label className="block text-sm text-t1">
              Keep closed cases for
              <span className="ml-2 font-data text-primary">{retention} days</span>
            </label>
            <input
              type="range"
              min={1}
              max={365}
              value={retention}
              onChange={(event) => setRetention(Number(event.target.value))}
              className="mt-2 w-full accent-primary"
            />
            <div className="mt-3">
              <KeyValue
                rows={[
                  ["Case database", "Local file, on this machine"],
                  ["Payload kept per packet", "1,460 bytes"],
                  ["Hashing", "SHA-256 at write time"],
                  ["Autosave", "Every 30 seconds"],
                  ["Export formats", "PDF · JSON · CSV · PCAP"],
                ]}
              />
            </div>
          </Panel>

          <Panel title="Quiet hours">
            <p className="text-sm text-t2">
              Activity inside this window is flagged for review, because a machine nobody is using
              should be quiet.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <input
                type="time"
                value={quietFrom}
                onChange={(event) => setQuietFrom(event.target.value)}
                className="border border-edge bg-d4 px-2 py-1.5 font-data text-xs text-t1 outline-none focus:border-focus"
              />
              <span className="font-data text-xs text-t3">to</span>
              <input
                type="time"
                value={quietTo}
                onChange={(event) => setQuietTo(event.target.value)}
                className="border border-edge bg-d4 px-2 py-1.5 font-data text-xs text-t1 outline-none focus:border-focus"
              />
              <Tag tone="accent">
                {quietFrom} – {quietTo}
              </Tag>
            </div>
            <div className="mt-4">
              <KeyValue
                rows={[
                  ["Owner", OWNER.name],
                  ["Contact", OWNER.email],
                  ["Name resolution", "Bundled tables only"],
                  ["Update checks", "Disabled — nothing phones home"],
                  ["Crash reporting", "Disabled"],
                ]}
              />
            </div>
          </Panel>
        </div>

        <Notice tone="ok" title="Fully self-contained">
          {OFFLINE_NOTICE}
        </Notice>
      </div>
    </div>
  );
}
