/**
 * Console chrome: icon rail, module sidebar, title strip and status bar.
 *
 * Wrapped around every screen by the pathless layout route so navigation,
 * live session readout and the legal footer are always present.
 */

import { useEffect, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Ban,
  Bell,
  Database,
  FileText,
  Folder,
  GitBranch,
  Globe,
  LayoutDashboard,
  List,
  Package,
  Radio,
  Scale,
  Search,
  Settings,
  Shield,
  UserRound,
} from "lucide-react";

import { APP, OWNER, COPYRIGHT } from "@/lib/owner";
import { SESSION, RISK, SEVERITY_COUNTS, STATS, formatNumber } from "@/lib/sample-data";
import { StatusDot } from "@/components/console";
import { cn } from "@/lib/utils";

type NavItem = {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  badge?: string;
};

const GROUPS: Array<{ title: string; items: NavItem[] }> = [
  {
    title: "Monitor",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard },
      { to: "/capture", label: "Live capture", icon: Radio },
      { to: "/packets", label: "Packets", icon: Package },
      { to: "/flows", label: "Conversations", icon: GitBranch },
    ],
  },
  {
    title: "Analyse",
    items: [
      { to: "/alerts", label: "Detections", icon: Bell, badge: String(SEVERITY_COUNTS.CRITICAL + SEVERITY_COUNTS.HIGH) },
      { to: "/dns", label: "Name lookups", icon: Globe },
      { to: "/intel", label: "Address intel", icon: Database },
      { to: "/timeline", label: "Timeline", icon: List },
      { to: "/search", label: "Search", icon: Search },
    ],
  },
  {
    title: "Respond",
    items: [
      { to: "/firewall", label: "Firewall", icon: Ban },
      { to: "/evidence", label: "Evidence", icon: Folder },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    title: "System",
    items: [
      { to: "/settings", label: "Settings", icon: Settings },
      { to: "/owner", label: "Owner", icon: UserRound },
      { to: "/legal", label: "Legal", icon: Scale },
    ],
  },
];

function useClock() {
  const [now, setNow] = useState("--:--:--");
  useEffect(() => {
    const update = () => setNow(new Date().toLocaleTimeString("en-GB", { hour12: false }));
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, []);
  return now;
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const clock = useClock();

  const riskTone =
    RISK.band === "CRITICAL" || RISK.band === "HIGH" ? "er" : RISK.band === "MEDIUM" ? "wa" : "ok";

  return (
    <div className="flex min-h-screen flex-col bg-d1 text-t1">
      {/* title strip */}
      <header className="flex h-11 shrink-0 items-center gap-4 border-b border-hair bg-d0 px-3">
        <Link to="/" className="flex items-center gap-2">
          <span className="grid size-6 place-items-center border border-primary/50 bg-primary/10 font-data text-[10px] font-bold text-primary">
            {APP.short}
          </span>
          <span className="hidden text-sm font-semibold tracking-wide text-t1 sm:inline">
            {APP.name}
          </span>
          <span className="hidden font-data text-[10px] text-t3 md:inline">v{APP.version}</span>
        </Link>

        <div className="ml-auto flex items-center gap-4">
          <span className="hidden items-center gap-1.5 font-data text-[11px] text-t2 lg:flex">
            <StatusDot tone="accent" pulse />
            CAPTURING
          </span>
          <span className="hidden font-data text-[11px] text-t3 md:inline">
            {SESSION.id}
          </span>
          <span
            className={cn(
              "flex items-center gap-1.5 border px-2 py-0.5 font-data text-[11px]",
              riskTone === "er"
                ? "border-er/40 bg-er/10 text-er"
                : riskTone === "wa"
                  ? "border-wa/40 bg-wa/10 text-wa"
                  : "border-ok/40 bg-ok/10 text-ok",
            )}
          >
            RISK {RISK.score} · {RISK.band}
          </span>
          <span className="font-data text-[11px] text-t2">{clock}</span>
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        {/* icon rail */}
        <nav className="hidden w-11 shrink-0 flex-col items-center gap-1 border-r border-hair bg-d0 py-2 md:flex">
          {GROUPS.flatMap((group) => group.items)
            .slice(0, 9)
            .map((item) => {
              const active = pathname === item.to;
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  title={item.label}
                  className={cn(
                    "grid size-8 place-items-center border transition-colors",
                    active
                      ? "border-primary/50 bg-primary/15 text-primary"
                      : "border-transparent text-t3 hover:border-edge hover:bg-d3 hover:text-t1",
                  )}
                >
                  <item.icon className="size-4" />
                </Link>
              );
            })}
          <span className="mt-auto font-data text-[9px] text-t3">OFF<br />LINE</span>
        </nav>

        {/* sidebar */}
        <aside className="hidden w-56 shrink-0 flex-col border-r border-hair bg-d1 lg:flex">
          <div className="border-b border-hair px-3 py-2.5">
            <p className="label-caps">Active session</p>
            <p className="mt-1 truncate font-data text-xs text-t1">{SESSION.name}</p>
            <p className="mt-1 font-data text-[10px] text-t3">
              {formatNumber(STATS.packets)} packets · {STATS.flows} conversations
            </p>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto py-2">
            {GROUPS.map((group) => (
              <div key={group.title} className="mb-3">
                <p className="label-caps px-3 py-1">{group.title}</p>
                {group.items.map((item) => {
                  const active = pathname === item.to;
                  return (
                    <Link
                      key={item.to}
                      to={item.to}
                      className={cn(
                        "flex items-center gap-2.5 border-l-2 px-3 py-1.5 text-[13px] transition-colors",
                        active
                          ? "border-l-primary bg-primary/10 text-t1"
                          : "border-l-transparent text-t2 hover:bg-d3 hover:text-t1",
                      )}
                    >
                      <item.icon className={cn("size-3.5", active ? "text-primary" : "text-t3")} />
                      <span className="truncate">{item.label}</span>
                      {item.badge && item.badge !== "0" ? (
                        <span className="ml-auto border border-er/40 bg-er/10 px-1 font-data text-[10px] text-er">
                          {item.badge}
                        </span>
                      ) : null}
                    </Link>
                  );
                })}
              </div>
            ))}
          </div>

          <div className="border-t border-hair px-3 py-2">
            <p className="label-caps">Operator</p>
            <p className="mt-1 truncate text-xs text-t1">{OWNER.name}</p>
            <p className="truncate font-data text-[10px] text-t3">{OWNER.handle}</p>
          </div>
        </aside>

        {/* workspace */}
        <main className="min-w-0 flex-1 overflow-x-hidden bg-d2">{children}</main>
      </div>

      {/* status bar */}
      <footer className="flex h-7 shrink-0 flex-wrap items-center gap-x-4 gap-y-0 border-t border-hair bg-d0 px-3 font-data text-[10px] text-t3">
        <span className="flex items-center gap-1.5 text-t2">
          <Activity className="size-3 text-ok" />
          Engine idle-ready
        </span>
        <span className="flex items-center gap-1.5">
          <Shield className="size-3" />
          No keys · no accounts · no telemetry
        </span>
        <span className="hidden sm:inline">Host {STATS.host}</span>
        <span className="hidden md:inline">Adapter {SESSION.adapter}</span>
        <span className="hidden lg:inline">{SESSION.integrity}</span>
        <span className="ml-auto hidden truncate sm:inline">{COPYRIGHT}</span>
      </footer>
    </div>
  );
}
