/**
 * Shared console primitives: panels, stat cards, severity pills, data tables.
 *
 * Every screen is built from these so spacing, borders and colour meaning stay
 * identical across the suite.
 */

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { Risk, Severity } from "@/lib/sample-data";

/* ── panel ───────────────────────────────────────────────────────────────── */

export function Panel({
  title,
  hint,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: string;
  hint?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section
      className={cn(
        "flex min-w-0 flex-col border border-hair bg-d2/80 backdrop-blur-[1px]",
        className,
      )}
    >
      {title ? (
        <header className="flex items-center justify-between gap-3 border-b border-hair bg-d1/60 px-3 py-2">
          <div className="flex min-w-0 items-baseline gap-2">
            <h2 className="label-caps text-t2">{title}</h2>
            {hint ? (
              <span className="truncate font-data text-[11px] text-t3">{hint}</span>
            ) : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cn("min-w-0 p-3", bodyClassName)}>{children}</div>
    </section>
  );
}

/* ── page header ─────────────────────────────────────────────────────────── */

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="grid-field border-b border-hair bg-d1/50 px-5 py-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <p className="label-caps text-primary">{eyebrow}</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-t1">{title}</h1>
          <p className="mt-1 max-w-3xl text-sm text-t2">{description}</p>
        </div>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </div>
    </div>
  );
}

/* ── stat card ───────────────────────────────────────────────────────────── */

export function StatCard({
  label,
  value,
  unit,
  sub,
  tone = "neutral",
  icon,
}: {
  label: string;
  value: string | number;
  unit?: string;
  sub?: string;
  tone?: "neutral" | "accent" | "ok" | "wa" | "er";
  icon?: ReactNode;
}) {
  const toneText = {
    neutral: "text-t1",
    accent: "text-primary",
    ok: "text-ok",
    wa: "text-wa",
    er: "text-er",
  }[tone];

  return (
    <div className="group relative overflow-hidden border border-hair bg-d2 p-3 transition-colors hover:border-edge">
      <div className="flex items-start justify-between gap-2">
        <span className="label-caps">{label}</span>
        {icon ? <span className="text-t3 transition-colors group-hover:text-primary">{icon}</span> : null}
      </div>
      <div className="mt-2 flex items-baseline gap-1">
        <span className={cn("font-data text-2xl font-semibold leading-none", toneText)}>
          {value}
        </span>
        {unit ? <span className="font-data text-xs text-t3">{unit}</span> : null}
      </div>
      {sub ? <p className="mt-1.5 font-data text-[11px] text-t3">{sub}</p> : null}
    </div>
  );
}

/* ── severity + risk pills ───────────────────────────────────────────────── */

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "border-er/50 bg-er/10 text-er",
  HIGH: "border-er/40 bg-er/5 text-er",
  MEDIUM: "border-wa/40 bg-wa/10 text-wa",
  LOW: "border-ok/40 bg-ok/10 text-ok",
  INFO: "border-in/40 bg-in/10 text-in",
};

const RISK_STYLE: Record<Risk, string> = {
  CRITICAL: "border-er/50 bg-er/10 text-er",
  HIGH: "border-er/40 bg-er/5 text-er",
  MEDIUM: "border-wa/40 bg-wa/10 text-wa",
  LOW: "border-ok/40 bg-ok/10 text-ok",
  NONE: "border-edge bg-d3 text-t3",
};

export function SeverityPill({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center border px-1.5 py-0.5 font-data text-[10px] font-semibold tracking-wider",
        SEVERITY_STYLE[severity],
      )}
    >
      {severity}
    </span>
  );
}

export function RiskPill({ risk }: { risk: Risk }) {
  return (
    <span
      className={cn(
        "inline-flex items-center border px-1.5 py-0.5 font-data text-[10px] font-semibold tracking-wider",
        RISK_STYLE[risk],
      )}
    >
      {risk}
    </span>
  );
}

export function Tag({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "accent" | "ok" | "wa" | "er" | "in";
}) {
  const styles = {
    neutral: "border-edge bg-d3 text-t2",
    accent: "border-primary/40 bg-primary/10 text-primary",
    ok: "border-ok/40 bg-ok/10 text-ok",
    wa: "border-wa/40 bg-wa/10 text-wa",
    er: "border-er/40 bg-er/10 text-er",
    in: "border-in/40 bg-in/10 text-in",
  }[tone];
  return (
    <span
      className={cn(
        "inline-flex items-center border px-1.5 py-0.5 font-data text-[10px] tracking-wide",
        styles,
      )}
    >
      {children}
    </span>
  );
}

/* ── status dot ──────────────────────────────────────────────────────────── */

export function StatusDot({
  tone = "ok",
  pulse = false,
}: {
  tone?: "ok" | "wa" | "er" | "idle" | "accent";
  pulse?: boolean;
}) {
  const colour = {
    ok: "bg-ok",
    wa: "bg-wa",
    er: "bg-er",
    idle: "bg-t3",
    accent: "bg-primary",
  }[tone];
  return (
    <span
      aria-hidden
      className={cn("inline-block size-[7px] rounded-full", colour, pulse && "pulse-dot")}
    />
  );
}

/* ── data table ──────────────────────────────────────────────────────────── */

export function DataTable({
  head,
  children,
  className,
}: {
  head: ReactNode[];
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("w-full overflow-x-auto", className)}>
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-edge bg-d1/60">
            {head.map((cell, index) => (
              <th
                key={index}
                className="label-caps whitespace-nowrap px-2.5 py-2 text-[10px]"
              >
                {cell}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Row({
  children,
  onClick,
  selected = false,
  tone,
}: {
  children: ReactNode;
  onClick?: () => void;
  selected?: boolean;
  tone?: "er" | "wa" | "ok" | "in";
}) {
  const accent = tone
    ? { er: "border-l-er", wa: "border-l-wa", ok: "border-l-ok", in: "border-l-in" }[tone]
    : "border-l-transparent";
  return (
    <tr
      onClick={onClick}
      className={cn(
        "border-b border-hair border-l-2 font-data text-xs transition-colors",
        accent,
        onClick && "cursor-pointer",
        selected ? "bg-d5/70 text-t1" : "odd:bg-d2 even:bg-d2/40 hover:bg-d4/70",
      )}
    >
      {children}
    </tr>
  );
}

export function Cell({
  children,
  className,
  mono = true,
}: {
  children: ReactNode;
  className?: string;
  mono?: boolean;
}) {
  return (
    <td
      className={cn(
        "whitespace-nowrap px-2.5 py-1.5 text-t2",
        mono ? "font-data" : "font-ui",
        className,
      )}
    >
      {children}
    </td>
  );
}

/* ── key/value list ──────────────────────────────────────────────────────── */

export function KeyValue({
  rows,
  columns = 1,
}: {
  rows: Array<[string, ReactNode]>;
  columns?: 1 | 2;
}) {
  return (
    <dl
      className={cn(
        "grid gap-x-6 gap-y-1.5",
        columns === 2 ? "sm:grid-cols-2" : "grid-cols-1",
      )}
    >
      {rows.map(([key, value]) => (
        <div
          key={key}
          className="flex items-baseline justify-between gap-3 border-b border-hair/60 pb-1.5"
        >
          <dt className="label-caps shrink-0">{key}</dt>
          <dd className="min-w-0 truncate font-data text-xs text-t1">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/* ── empty + notice ──────────────────────────────────────────────────────── */

export function Notice({
  tone = "accent",
  title,
  children,
}: {
  tone?: "accent" | "wa" | "er" | "ok";
  title: string;
  children?: ReactNode;
}) {
  const styles = {
    accent: "border-primary/30 bg-primary/5",
    wa: "border-wa/30 bg-wa/5",
    er: "border-er/30 bg-er/5",
    ok: "border-ok/30 bg-ok/5",
  }[tone];
  const text = {
    accent: "text-primary",
    wa: "text-wa",
    er: "text-er",
    ok: "text-ok",
  }[tone];
  return (
    <div className={cn("border p-3", styles)}>
      <p className={cn("label-caps", text)}>{title}</p>
      {children ? <div className="mt-1.5 text-sm text-t2">{children}</div> : null}
    </div>
  );
}

/* ── bar meter ───────────────────────────────────────────────────────────── */

export function Meter({
  value,
  max,
  tone = "accent",
}: {
  value: number;
  max: number;
  tone?: "accent" | "ok" | "wa" | "er";
}) {
  const percent = max <= 0 ? 0 : Math.min(100, Math.round((value / max) * 100));
  const colour = {
    accent: "bg-primary",
    ok: "bg-ok",
    wa: "bg-wa",
    er: "bg-er",
  }[tone];
  return (
    <div className="h-1.5 w-full overflow-hidden bg-d4">
      <div className={cn("h-full transition-[width]", colour)} style={{ width: `${percent}%` }} />
    </div>
  );
}
