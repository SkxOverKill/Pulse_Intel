"use client";

import { useActionState } from "react";
import Link from "next/link";
import { AlertTriangle, ExternalLink, Search } from "lucide-react";
import { useFormStatus } from "react-dom";
import { Field, FormError, TextInput } from "@/components/ui/form";
import { HorizontalBarChart } from "@/components/ui/charts";
import { cn } from "@/lib/utils";
import type { ActionResult } from "@/lib/actions";
import { lookupIndicator, type LookupOutcome, type LookupResult } from "./actions";

/** VirusTotal's per-engine detection counts, shown as a bar chart when present. */
function vtDetectionData(o: LookupOutcome) {
  const f = o.fields;
  if (o.provider !== "virustotal") return null;
  const entries = [
    { label: "Malicious", value: Number(f.maliciousEngines ?? 0), color: "var(--color-sev-critical)" },
    { label: "Suspicious", value: Number(f.suspiciousEngines ?? 0), color: "var(--color-sev-medium)" },
    { label: "Harmless", value: Number(f.harmlessEngines ?? 0), color: "var(--color-ok)" },
    { label: "Undetected", value: Number(f.undetectedEngines ?? 0), color: "var(--color-ink-faint)" },
  ].filter((d) => d.value > 0);
  return entries.length > 0 ? entries : null;
}

type ProviderOption = { name: string; label: string };

const STATUS_STYLES: Record<string, string> = {
  fetched: "border-line bg-surface-2 text-ink",
  cached: "border-line bg-surface-2 text-ink-muted",
  skipped: "border-line bg-surface-2 text-ink-faint",
  rate_limited: "border-warn/40 bg-warn/10 text-warn",
  error: "border-danger/40 bg-danger/10 text-danger",
};

const VERDICT_STYLES: Record<string, string> = {
  MALICIOUS: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical",
  SUSPICIOUS: "border-sev-medium/40 bg-sev-medium/10 text-sev-medium",
  BENIGN: "border-ok/40 bg-ok/10 text-ok",
  UNKNOWN: "border-line bg-surface-2 text-ink-faint",
};

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-md bg-brand px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-60"
    >
      <Search className="size-4" />
      {pending ? "Looking up…" : "Look up"}
    </button>
  );
}

export function LookupForm({ providers }: { providers: ProviderOption[] }) {
  const [state, formAction] = useActionState<ActionResult<LookupResult>, FormData>(
    lookupIndicator,
    { ok: false, error: "" },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;
  const result = state.ok ? state.data : null;

  return (
    <div className="space-y-4">
      <form action={formAction} className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="grid gap-4">
          <Field
            label="Indicator"
            name="value"
            errors={errors}
            hint="IP, domain, URL, hash, or CVE — type is auto-detected"
            required
          >
            <TextInput
              name="value"
              required
              className="font-mono"
              placeholder="8.8.8.8, evil.com, 44d88612fea8a8f36de82e1278abb02f…"
            />
          </Field>

          <div>
            <p className="mb-1.5 text-xs font-medium text-ink-muted">Providers</p>
            <div className="flex flex-wrap gap-3">
              {providers.map((p) => (
                <label key={p.name} className="flex items-center gap-1.5 text-sm text-ink">
                  <input
                    type="checkbox"
                    name="providers"
                    value={p.name}
                    defaultChecked
                    className="size-4 rounded border-line bg-base accent-brand"
                  />
                  {p.label}
                </label>
              ))}
            </div>
            {providers.length === 0 ? (
              <p className="mt-1 text-xs text-danger">
                No providers are configured — add API keys in .env first.
              </p>
            ) : null}
          </div>
        </div>

        <div className="mt-4">
          <SubmitButton />
        </div>

        <FormError error={!state.ok ? state.error : undefined} />
      </form>

      {result ? (
        <div className="rounded-[--radius-card] border border-line bg-surface p-5">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="text-xs text-ink-faint">{result.type}</p>
              <p className="truncate font-mono text-sm text-ink" title={result.value}>
                {result.value}
              </p>
            </div>
            <Link
              href={`/indicators/${result.indicatorId}`}
              className="inline-flex shrink-0 items-center gap-1 text-xs text-brand hover:underline"
            >
              View indicator <ExternalLink className="size-3" />
            </Link>
          </div>

          {result.whitelisted ? (
            <p className="mb-3 flex items-center gap-2 rounded-md border border-line bg-surface-2 px-3 py-2 text-xs text-ink-muted">
              <AlertTriangle className="size-3.5 shrink-0" />
              This value is whitelisted — never enriched or alerted on, so every provider was
              skipped on purpose.
            </p>
          ) : null}

          <div className="space-y-3">
            {result.outcomes.map((o) => {
              const fieldEntries = Object.entries(o.fields).filter(
                ([, v]) => v !== null && v !== undefined && v !== "",
              );
              const chartData = vtDetectionData(o);
              return (
                <div key={o.provider} className="overflow-hidden rounded-md border border-line">
                  <div
                    className={cn(
                      "flex items-center justify-between gap-3 px-3 py-2",
                      STATUS_STYLES[o.status],
                    )}
                  >
                    <span className="text-sm font-medium">{o.label}</span>
                    <span className="flex items-center gap-2 text-xs">
                      {o.verdict ? (
                        <>
                          <span
                            className={cn(
                              "rounded border px-1.5 py-0.5 font-medium uppercase tracking-wide",
                              VERDICT_STYLES[o.verdict] ?? VERDICT_STYLES.UNKNOWN,
                            )}
                          >
                            {o.verdict}
                          </span>
                          {o.score != null ? <span className="tabular">{o.score}/100</span> : null}
                          {o.status === "cached" ? (
                            <span className="text-ink-faint">cached</span>
                          ) : null}
                        </>
                      ) : (
                        <span title={o.detail ?? undefined}>{o.detail}</span>
                      )}
                    </span>
                  </div>

                  {chartData ? (
                    <div className="border-t border-line bg-surface-2/40">
                      <HorizontalBarChart data={chartData} />
                    </div>
                  ) : null}

                  {fieldEntries.length > 0 ? (
                    <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 border-t border-line bg-surface-2/40 px-3 py-2.5 sm:grid-cols-3">
                      {fieldEntries.map(([key, value]) => (
                        <div key={key} className="min-w-0">
                          <dt className="truncate text-[10px] uppercase tracking-wide text-ink-faint">
                            {key.replace(/([A-Z])/g, " $1").toLowerCase()}
                          </dt>
                          <dd className="truncate text-xs text-ink" title={String(value)}>
                            {String(value)}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  ) : null}
                </div>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}
