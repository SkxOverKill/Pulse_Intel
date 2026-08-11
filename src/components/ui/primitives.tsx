import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { Severity, Tlp } from "@/generated/prisma/enums";

export function Card({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={cn(
        "rounded-[--radius-card] border border-line bg-surface",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  hint,
  action,
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-line px-4 py-3">
      <div className="min-w-0">
        <h2 className="truncate text-sm font-semibold text-ink">{title}</h2>
        {hint ? (
          <p className="mt-0.5 truncate text-xs text-ink-muted">{hint}</p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

const SEVERITY_DOT: Record<Severity, string> = {
  CRITICAL: "bg-sev-critical",
  HIGH: "bg-sev-high",
  MEDIUM: "bg-sev-medium",
  LOW: "bg-sev-low",
  INFO: "bg-sev-info",
};

const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-sev-critical",
  HIGH: "text-sev-high",
  MEDIUM: "text-sev-medium",
  LOW: "text-sev-low",
  INFO: "text-sev-info",
};

/// Dot + label rather than a filled/bordered pill — severity is read at a
/// glance down a whole column, and a bare dot scans faster than a badge.
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide">
      <span className={cn("size-1.5 shrink-0 rounded-[2px]", SEVERITY_DOT[severity])} />
      <span className={SEVERITY_TEXT[severity]}>{severity}</span>
    </span>
  );
}

const TLP_STYLES: Record<Tlp, string> = {
  CLEAR: "border-tlp-clear/40 bg-tlp-clear/10 text-tlp-clear",
  GREEN: "border-tlp-green/40 bg-tlp-green/10 text-tlp-green",
  AMBER: "border-tlp-amber/40 bg-tlp-amber/10 text-tlp-amber",
  AMBER_STRICT: "border-tlp-amber-strict/40 bg-tlp-amber-strict/10 text-tlp-amber-strict",
  RED: "border-tlp-red/40 bg-tlp-red/10 text-tlp-red",
};

const TLP_LABELS: Record<Tlp, string> = {
  CLEAR: "TLP:CLEAR",
  GREEN: "TLP:GREEN",
  AMBER: "TLP:AMBER",
  AMBER_STRICT: "TLP:AMBER+STRICT",
  RED: "TLP:RED",
};

export function TlpBadge({ tlp }: { tlp: Tlp }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] font-medium",
        TLP_STYLES[tlp],
      )}
    >
      {TLP_LABELS[tlp]}
    </span>
  );
}

/// Confidence is shown as a bar rather than a bare number so analysts read it
/// as the soft signal it is. Attribution is opinion, not fact.
export function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value));
  const tone =
    pct >= 75 ? "bg-ok" : pct >= 50 ? "bg-brand" : pct >= 25 ? "bg-warn" : "bg-danger";
  return (
    <span className="inline-flex items-center gap-2" title={`Confidence ${pct}%`}>
      <span className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3">
        <span className={cn("block h-full rounded-full", tone)} style={{ width: `${pct}%` }} />
      </span>
      <span className="tabular text-xs text-ink-muted">{pct}%</span>
    </span>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      <p className="max-w-md text-sm text-ink-muted">{description}</p>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}
