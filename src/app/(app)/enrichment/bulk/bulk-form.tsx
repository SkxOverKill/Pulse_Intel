"use client";

import { Fragment, useActionState, useMemo } from "react";
import { useFormStatus } from "react-dom";
import { AlertTriangle, Download, Search } from "lucide-react";
import { FormError } from "@/components/ui/form";
import { cn } from "@/lib/utils";
import type { ActionResult } from "@/lib/actions";
import { bulkLookup, type BulkLookupResult, type BulkRow } from "./actions";

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
      {pending ? "Looking up…" : "Look up all"}
    </button>
  );
}

/** Every distinct detail-field key seen for a given provider, across all rows. */
function fieldKeysFor(rows: BulkRow[], provider: string): string[] {
  const keys = new Set<string>();
  for (const row of rows) {
    const outcome = row.outcomes.find((o) => o.provider === provider);
    if (outcome) for (const k of Object.keys(outcome.fields)) keys.add(k);
  }
  return Array.from(keys);
}

function toCsv(rows: BulkRow[], providers: string[]): string {
  const providerFieldKeys = new Map(providers.map((p) => [p, fieldKeysFor(rows, p)]));

  const headers = ["input", "type", "value", "whitelisted", "error"];
  for (const p of providers) {
    headers.push(`${p}_status`, `${p}_verdict`, `${p}_score`);
    for (const k of providerFieldKeys.get(p) ?? []) headers.push(`${p}_${k}`);
  }

  const escape = (v: unknown) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };

  const lines = [headers.join(",")];
  for (const row of rows) {
    const cells: unknown[] = [row.input, row.type, row.value, row.whitelisted, row.error];
    for (const p of providers) {
      const outcome = row.outcomes.find((o) => o.provider === p);
      cells.push(outcome?.status ?? "", outcome?.verdict ?? "", outcome?.score ?? "");
      for (const k of providerFieldKeys.get(p) ?? []) cells.push(outcome?.fields[k] ?? "");
    }
    lines.push(cells.map(escape).join(","));
  }
  return lines.join("\n");
}

function downloadCsv(rows: BulkRow[], providers: string[]) {
  const csv = toCsv(rows, providers);
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `bulk-lookup-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export function BulkLookupForm({ providers }: { providers: ProviderOption[] }) {
  const [state, formAction] = useActionState<ActionResult<BulkLookupResult>, FormData>(
    bulkLookup,
    { ok: false, error: "" },
  );

  const rows = useMemo(() => (state.ok ? state.data.rows : []), [state]);
  const selectedProviders = useMemo(() => providers.map((p) => p.name), [providers]);

  const usedProviders = useMemo(
    () =>
      selectedProviders.filter((p) => rows.some((r) => r.outcomes.some((o) => o.provider === p))),
    [rows, selectedProviders],
  );
  const providerFieldKeys = useMemo(
    () => new Map(usedProviders.map((p) => [p, fieldKeysFor(rows, p)])),
    [rows, usedProviders],
  );

  return (
    <div className="space-y-4">
      <form action={formAction} className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="grid gap-4">
          <div>
            <label htmlFor="values" className="mb-1.5 block text-xs font-medium text-ink-muted">
              Indicators — one per line
            </label>
            <textarea
              id="values"
              name="values"
              required
              rows={8}
              className="w-full rounded-md border border-line bg-base px-3 py-2 font-mono text-xs text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none"
              placeholder={"8.8.8.8\nevil.com\n44d88612fea8a8f36de82e1278abb02f\nCVE-2024-3400"}
            />
            <p className="mt-1 text-xs text-ink-faint">Up to 200 lines per submission.</p>
          </div>

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
                No providers are configured — set keys in Settings, or add ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY to .env.
              </p>
            ) : null}
          </div>
        </div>

        <div className="mt-4">
          <SubmitButton />
        </div>

        <FormError error={!state.ok ? state.error : undefined} />
      </form>

      {state.ok && state.data.truncated ? (
        <p className="flex items-center gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">
          <AlertTriangle className="size-3.5 shrink-0" />
          More than 200 lines were submitted — only the first 200 were processed.
        </p>
      ) : null}

      {rows.length > 0 ? (
        <div className="rounded-[--radius-card] border border-line bg-surface">
          <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
            <p className="text-sm font-semibold text-ink">
              {rows.length} result{rows.length === 1 ? "" : "s"}
            </p>
            <button
              type="button"
              onClick={() => downloadCsv(rows, usedProviders)}
              className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:bg-surface-3"
            >
              <Download className="size-3.5" />
              Export CSV
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-xs">
              <thead>
                <tr>
                  <th className="border-b border-line px-3 py-2 text-left font-medium uppercase tracking-wide text-ink-faint">
                    Indicator
                  </th>
                  {usedProviders.map((p) => (
                    <th
                      key={p}
                      colSpan={2 + (providerFieldKeys.get(p)?.length ?? 0)}
                      className="border-b border-l border-line px-3 py-2 text-left font-medium uppercase tracking-wide text-ink-faint"
                    >
                      {providers.find((x) => x.name === p)?.label ?? p}
                    </th>
                  ))}
                </tr>
                <tr>
                  <th className="border-b border-line px-3 py-1.5" />
                  {usedProviders.map((p) => (
                    <Fragment key={p}>
                      <th className="border-b border-l border-line px-3 py-1.5 text-left font-normal text-ink-faint">
                        Verdict
                      </th>
                      <th className="border-b border-line px-3 py-1.5 text-left font-normal text-ink-faint">
                        Score
                      </th>
                      {(providerFieldKeys.get(p) ?? []).map((k) => (
                        <th
                          key={k}
                          className="border-b border-line px-3 py-1.5 text-left font-normal capitalize text-ink-faint"
                        >
                          {k.replace(/([A-Z])/g, " $1").toLowerCase()}
                        </th>
                      ))}
                    </Fragment>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, i) => (
                  <tr key={i} className="hover:bg-surface-2">
                    <td className="border-b border-line/60 px-3 py-2 align-top">
                      <p className="font-mono text-ink">{row.value ?? row.input}</p>
                      <p className="text-[11px] text-ink-faint">
                        {row.type ?? "—"}
                        {row.whitelisted ? " · whitelisted" : ""}
                        {row.error ? (
                          <span className="text-danger"> · {row.error}</span>
                        ) : null}
                      </p>
                    </td>
                    {usedProviders.map((p) => {
                      const outcome = row.outcomes.find((o) => o.provider === p);
                      const fieldKeys = providerFieldKeys.get(p) ?? [];
                      if (!outcome) {
                        return (
                          <td
                            key={p}
                            colSpan={2 + fieldKeys.length}
                            className="border-b border-l border-line/60 px-3 py-2 align-top text-ink-faint"
                          >
                            —
                          </td>
                        );
                      }
                      if (outcome.status !== "fetched" && outcome.status !== "cached") {
                        return (
                          <td
                            key={p}
                            colSpan={2 + fieldKeys.length}
                            className="border-b border-l border-line/60 px-3 py-2 align-top"
                          >
                            <span
                              className={cn(
                                "rounded border px-1.5 py-0.5 text-[11px]",
                                STATUS_STYLES[outcome.status],
                              )}
                              title={outcome.detail ?? undefined}
                            >
                              {outcome.status.replace("_", " ")}
                            </span>
                          </td>
                        );
                      }
                      return (
                        <Fragment key={p}>
                          <td className="border-b border-l border-line/60 px-3 py-2 align-top">
                            {outcome.verdict ? (
                              <span
                                className={cn(
                                  "rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide",
                                  VERDICT_STYLES[outcome.verdict] ?? VERDICT_STYLES.UNKNOWN,
                                )}
                              >
                                {outcome.verdict}
                              </span>
                            ) : (
                              <span className="text-ink-faint">—</span>
                            )}
                          </td>
                          <td className="tabular border-b border-line/60 px-3 py-2 align-top text-ink-muted">
                            {outcome.score ?? "—"}
                          </td>
                          {fieldKeys.map((k) => (
                            <td
                              key={k}
                              className="border-b border-line/60 px-3 py-2 align-top text-ink-muted"
                            >
                              {outcome.fields[k] === null || outcome.fields[k] === undefined
                                ? "—"
                                : String(outcome.fields[k])}
                            </td>
                          ))}
                        </Fragment>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}
