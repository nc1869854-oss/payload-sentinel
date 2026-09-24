import { createFileRoute } from "@tanstack/react-router";
import {
  AtSign,
  Cpu,
  Globe,
  Mail,
  MapPin,
  Shield,
  UserRound,
} from "lucide-react";

import {
  KeyValue,
  Notice,
  PageHeader,
  Panel,
  StatCard,
  Tag,
} from "@/components/console";
import {
  APP,
  COPYRIGHT,
  OFFLINE_NOTICE,
  OWNER,
  SOCIAL_LINKS,
  type SocialLink,
} from "@/lib/owner";

export const Route = createFileRoute("/owner")({
  head: () => ({
    meta: [
      { title: "Owner — Payload Capture Suite" },
      {
        name: "description",
        content: `Meet the owner of Payload Capture Suite: ${OWNER.name}, ${OWNER.role}. Contact and social profiles.`,
      },
      { property: "og:title", content: "Owner — Payload Capture Suite" },
      {
        property: "og:description",
        content: `${OWNER.name} — ${OWNER.role}. Email ${OWNER.email}, social ${OWNER.handle}.`,
      },
    ],
  }),
  component: OwnerPage,
});

/* ── social icon mapping ─────────────────────────────────────────────────── */

const SOCIAL_ICON: Record<SocialLink["icon"], typeof Globe> = {
  instagram: Globe,
  twitter: AtSign,
  github: Globe,
  youtube: Globe,
  linkedin: Globe,
  facebook: Globe,
  send: Globe,
};

function OwnerPage() {
  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow="System"
        title="Owner"
        description="The person behind the suite, how to reach them, and where to follow the project."
      />

      <div className="grid gap-3 p-4 lg:grid-cols-3">
        {/* ── Owner identity card ─────────────────────────────────────────── */}
        <Panel title="Owner" className="lg:col-span-2">
          <div className="flex items-start gap-4">
            <div className="grid size-16 shrink-0 place-items-center border border-primary/40 bg-primary/10 text-primary">
              <UserRound className="size-8" />
            </div>
            <div className="min-w-0">
              <h2 className="text-xl font-semibold text-t1">{OWNER.name}</h2>
              <p className="mt-0.5 text-sm text-t2">{OWNER.role}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <Tag tone="accent">
                  <Mail className="mr-1 inline size-3" />
                  {OWNER.email}
                </Tag>
                <Tag tone="accent">
                  <AtSign className="mr-1 inline size-3" />
                  {OWNER.handle}
                </Tag>
                <Tag tone="neutral">
                  <MapPin className="mr-1 inline size-3" />
                  {OWNER.location}
                </Tag>
              </div>
            </div>
          </div>

          <div className="mt-5">
            <KeyValue
              columns={2}
              rows={[
                ["Application", APP.name],
                ["Version", APP.version],
                ["Edition", APP.edition],
                ["Tagline", APP.tagline],
                ["Owner", OWNER.name],
                ["Role", OWNER.role],
                ["Email", OWNER.email],
                ["Social handle", OWNER.handle],
              ]}
            />
          </div>
        </Panel>

        {/* ── Offline notice ──────────────────────────────────────────────── */}
        <div className="flex flex-col gap-3">
          <StatCard
            label="Outbound connections"
            value="0"
            tone="ok"
            sub="By design"
            icon={<Shield className="size-4" />}
          />
          <StatCard
            label="Version"
            value={APP.version}
            sub={APP.edition}
            icon={<Cpu className="size-4" />}
          />
          <Notice tone="ok" title="No keys · no accounts · no telemetry">
            <p className="text-xs text-t2">{OFFLINE_NOTICE}</p>
          </Notice>
        </div>
      </div>

      {/* ── Social profiles ────────────────────────────────────────────────── */}
      <div className="px-4 pb-4">
        <Panel title="Social profiles" hint={`All profiles follow ${OWNER.handle}`}>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {SOCIAL_LINKS.map((link) => {
              const Icon = SOCIAL_ICON[link.icon];
              return (
                <a
                  key={link.label}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group flex items-center gap-3 border border-hair bg-d3/60 p-3 transition-colors hover:border-primary/40 hover:bg-d3"
                >
                  <span className="grid size-9 shrink-0 place-items-center border border-edge bg-d4 text-t3 transition-colors group-hover:border-primary/40 group-hover:text-primary">
                    <Icon className="size-4" />
                  </span>
                  <div className="min-w-0">
                    <p className="truncate text-sm text-t1">{link.label}</p>
                    <p className="truncate font-data text-[11px] text-t3">{OWNER.handle}</p>
                  </div>
                </a>
              );
            })}
          </div>
        </Panel>
      </div>

      {/* ── About the application ──────────────────────────────────────────── */}
      <div className="px-4 pb-4">
        <Panel title="About the application">
          <p className="text-sm text-t2">{APP.description}</p>
          <div className="mt-4 border-t border-hair pt-3">
            <p className="font-data text-[11px] text-t3">{COPYRIGHT}</p>
          </div>
        </Panel>
      </div>
    </div>
  );
}
