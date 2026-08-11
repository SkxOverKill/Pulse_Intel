"use client";

import { useActionState, useState, useMemo, useTransition, useEffect } from "react";
import Link from "next/link";
import { CheckCircle2, FileSearch, ShieldOff, TriangleAlert, Zap } from "lucide-react";
import {
  ConfidenceInput,
  Field,
  FormError,
  Select,
  SubmitButton,
  TextArea,
  TextInput,
} from "@/components/ui/form";
import { bulkIngest, type BulkState } from "../actions";
import { extractIocs } from "@/lib/ioc/extract";

const SEVERITIES = [
  { value: "MEDIUM", label: "Medium" },
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "LOW", label: "Low" },
  { value: "INFO", label: "Info" },
];

const TLPS = [
  { value: "AMBER", label: "TLP:AMBER" },
  { value: "CLEAR", label: "TLP:CLEAR" },
  { value: "GREEN", label: "TLP:GREEN" },
  { value: "AMBER_STRICT", label: "TLP:AMBER+STRICT" },
  { value: "RED", label: "TLP:RED" },
];

const PLACEHOLDER = `# Paste anything — structured IOC lists or raw threat intel reports.
# The extractor handles both modes automatically.

# --- Structured list ---
8.8.8.8
evil[.]com
hxxps://bad.example.com/payload
d41d8cd98f00b204e9800998ecf8427e
CVE-2024-3400

# --- Or paste a full report paragraph ---
# "The actor used IP 203.0.113.42 and connected to malware.badactor.ru
#  downloading SHA256 a3f1...c9d2. A scheduled task was created at
#  HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."`;

const TYPE_ORDER = [
  "IPV4", "IPV6", "DOMAIN", "URL", "SHA256", "SHA1", "MD5",
  "EMAIL", "CVE", "BTC_ADDRESS", "REGISTRY_KEY", "MUTEX",
  "USER_AGENT", "ASN", "FILENAME",
];

const TYPE_LABELS: Record<string, string> = {
  IPV4: "IPv4",
  IPV6: "IPv6",
  DOMAIN: "Domain",
  URL: "URL",
  SHA256: "SHA-256",
  SHA1: "SHA-1",
  MD5: "MD5",
  EMAIL: "Email",
  CVE: "CVE",
  BTC_ADDRESS: "Bitcoin",
  REGISTRY_KEY: "Registry key",
  MUTEX: "Mutex",
  USER_AGENT: "User-agent",
  ASN: "ASN",
  FILENAME: "Filename",
};

const TYPE_COLORS: Record<string, string> = {
  IPV4: "bg-blue-500/15 text-blue-400 border-blue-500/25",
  IPV6: "bg-blue-500/10 text-blue-300 border-blue-500/20",
  DOMAIN: "bg-purple-500/15 text-purple-400 border-purple-500/25",
  URL: "bg-violet-500/15 text-violet-400 border-violet-500/25",
  SHA256: "bg-orange-500/15 text-orange-400 border-orange-500/25",
  SHA1: "bg-orange-500/10 text-orange-300 border-orange-500/20",
  MD5: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  EMAIL: "bg-teal-500/15 text-teal-400 border-teal-500/25",
  CVE: "bg-red-500/15 text-red-400 border-red-500/25",
  BTC_ADDRESS: "bg-amber-500/15 text-amber-400 border-amber-500/25",
  REGISTRY_KEY: "bg-slate-500/15 text-slate-400 border-slate-500/25",
  MUTEX: "bg-slate-500/10 text-slate-300 border-slate-500/20",
  USER_AGENT: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
  ASN: "bg-cyan-500/15 text-cyan-400 border-cyan-500/25",
  FILENAME: "bg-green-500/10 text-green-400 border-green-500/20",
};

// Debounce hook — delays updating debounced value until ms after last change.
function useDebounce<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return debounced;
}

export function ImportForm({
  sources,
}: {
  sources: { id: string; name: string }[];
}) {
  const [state, formAction] = useActionState<BulkState, FormData>(bulkIngest, {
    ok: true,
    data: {
      created: 0,
      updated: 0,
      duplicatesInInput: 0,
      whitelisted: 0,
      unparsed: [],
      total: 0,
    },
  });

  const [text, setText] = useState("");
  const [, startTransition] = useTransition();

  // Debounce so extraction doesn't run on every single keystroke.
  const debouncedText = useDebounce(text, 300);

  // Extract live — runs in browser, no round-trip.
  const preview = useMemo(() => {
    if (!debouncedText.trim()) return null;
    return extractIocs(debouncedText);
  }, [debouncedText]);

  const errors = !state.ok ? state.fieldErrors : undefined;
  const report = state.ok && state.data.total > 0 ? state.data : null;

  const sortedTypes = preview
    ? Object.keys(preview.byType).sort(
        (a, b) =>
          (TYPE_ORDER.indexOf(a) === -1 ? 99 : TYPE_ORDER.indexOf(a)) -
          (TYPE_ORDER.indexOf(b) === -1 ? 99 : TYPE_ORDER.indexOf(b)),
      )
    : [];

  return (
    <div className="space-y-4">
      {report ? <ImportReport report={report} /> : null}

      <form action={formAction} className="space-y-5">
        <div className="rounded-[--radius-card] border border-line bg-surface p-5">
          <div className="space-y-4">
            <Field
              label="Indicators"
              name="text"
              errors={errors}
              required
              hint="Paste a structured list or a full threat intel report — type is detected automatically"
            >
              <TextArea
                name="text"
                required
                rows={12}
                placeholder={PLACEHOLDER}
                className="font-mono text-xs"
                value={text}
                onChange={(e) => {
                  const val = e.target.value;
                  startTransition(() => setText(val));
                }}
              />
            </Field>

            {/* Live extraction preview */}
            {preview && preview.total > 0 ? (
              <LivePreview
                preview={preview}
                sortedTypes={sortedTypes}
              />
            ) : debouncedText.trim().length > 20 && preview && preview.total === 0 ? (
              <div className="flex items-center gap-2 rounded-md border border-line bg-surface-2 px-3 py-2.5 text-xs text-ink-muted">
                <FileSearch className="size-3.5 shrink-0" />
                No recognizable indicators found yet — keep typing or paste a
                full value on its own line.
              </div>
            ) : null}

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Severity" name="severity" errors={errors}>
                <Select name="severity" options={SEVERITIES} defaultValue="MEDIUM" />
              </Field>

              <Field label="TLP" name="tlp" errors={errors}>
                <Select name="tlp" options={TLPS} defaultValue="AMBER" />
              </Field>

              <Field label="Tags" name="tags" errors={errors} hint="comma separated">
                <TextInput name="tags" placeholder="phishing, qakbot" />
              </Field>

              <Field
                label="Source"
                name="sourceId"
                errors={errors}
                hint="where these came from"
              >
                <Select
                  name="sourceId"
                  options={[
                    { value: "", label: "Manual entry" },
                    ...sources.map((s) => ({ value: s.id, label: s.name })),
                  ]}
                />
              </Field>

              <div className="sm:col-span-2">
                <Field
                  label="Confidence"
                  name="confidence"
                  errors={errors}
                  hint="applied to every indicator in this batch"
                >
                  <ConfidenceInput defaultValue={50} />
                </Field>
              </div>
            </div>
          </div>
        </div>

        <FormError error={!state.ok ? state.error : undefined} />

        <div className="flex items-center gap-2">
          <SubmitButton>
            {preview && preview.total > 0
              ? `Import ${preview.total} indicator${preview.total === 1 ? "" : "s"}`
              : "Import"}
          </SubmitButton>
          <Link
            href="/indicators"
            className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
          >
            Back to indicators
          </Link>
        </div>
      </form>
    </div>
  );
}

// --------------------------------------------------------------------------
// Live preview panel
// --------------------------------------------------------------------------

function LivePreview({
  preview,
  sortedTypes,
}: {
  preview: ReturnType<typeof extractIocs>;
  sortedTypes: string[];
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-md border border-brand/30 bg-brand/5 p-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap className="size-3.5 text-brand" />
          <span className="text-xs font-semibold text-ink">
            Detected {preview.total} indicator{preview.total === 1 ? "" : "s"}
          </span>
        </div>
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="text-[11px] text-ink-muted hover:text-ink"
        >
          {expanded ? "Hide values" : "Show values"}
        </button>
      </div>

      {/* Type breakdown */}
      <div className="flex flex-wrap gap-1.5">
        {sortedTypes.map((type) => {
          const color = TYPE_COLORS[type] ?? "bg-surface-2 text-ink-muted border-line";
          return (
            <span
              key={type}
              className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-medium ${color}`}
            >
              <span className="font-mono font-bold">{preview.byType[type]}</span>
              {TYPE_LABELS[type] ?? type}
            </span>
          );
        })}
      </div>

      {/* Value list — shown only when expanded */}
      {expanded ? (
        <div className="mt-2.5 max-h-52 overflow-y-auto rounded border border-line bg-surface">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="border-b border-line">
                <th className="px-2 py-1.5 text-left font-medium text-ink-muted">Type</th>
                <th className="px-2 py-1.5 text-left font-mono font-medium text-ink-muted">Value</th>
              </tr>
            </thead>
            <tbody>
              {preview.indicators.map((ind, i) => (
                <tr key={i} className="border-b border-line/50 last:border-0">
                  <td className="px-2 py-1 text-ink-muted">
                    {TYPE_LABELS[ind.type] ?? ind.type}
                  </td>
                  <td className="max-w-xs truncate px-2 py-1 font-mono text-ink">
                    {ind.normalizedValue}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {preview.unparsedCount > 0 ? (
        <p className="mt-2 text-[11px] text-ink-faint">
          {preview.unparsedCount} line{preview.unparsedCount === 1 ? "" : "s"} not recognized
        </p>
      ) : null}
    </div>
  );
}

// --------------------------------------------------------------------------
// Post-import report
// --------------------------------------------------------------------------

type Report = {
  created: number;
  updated: number;
  duplicatesInInput: number;
  whitelisted: number;
  unparsed: string[];
  total: number;
};

function ImportReport({ report }: { report: Report }) {
  return (
    <div className="rounded-[--radius-card] border border-line bg-surface p-4">
      <div className="mb-3 flex items-center gap-2">
        <CheckCircle2 className="size-4 text-ok" />
        <h2 className="text-sm font-semibold text-ink">Import complete</h2>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Created" value={report.created} tone="text-ok" />
        <Stat label="Already known" value={report.updated} tone="text-ink" />
        <Stat
          label="Duplicates in paste"
          value={report.duplicatesInInput}
          tone="text-ink-muted"
        />
        <Stat label="Whitelisted" value={report.whitelisted} tone="text-warn" />
      </div>

      {report.whitelisted > 0 ? (
        <p className="mt-3 flex items-start gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">
          <ShieldOff className="mt-px size-3.5 shrink-0" />
          {report.whitelisted} indicator{report.whitelisted === 1 ? "" : "s"} matched
          the whitelist (private ranges, public resolvers, core infrastructure).
          Stored for reference, but excluded from exports and alerting.
        </p>
      ) : null}

      {report.unparsed.length > 0 ? (
        <div className="mt-3 rounded-md border border-danger/40 bg-danger/10 px-3 py-2">
          <p className="flex items-center gap-2 text-xs font-medium text-danger">
            <TriangleAlert className="size-3.5" />
            {report.unparsed.length} line
            {report.unparsed.length === 1 ? "" : "s"} could not be classified and
            {report.unparsed.length === 1 ? " was" : " were"} not imported
          </p>
          <ul className="mt-1.5 max-h-32 overflow-y-auto font-mono text-[11px] text-danger/85">
            {report.unparsed.slice(0, 50).map((line, i) => (
              <li key={i} className="truncate">
                {line}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: string;
}) {
  return (
    <div className="rounded-md border border-line bg-surface-2 px-3 py-2">
      <p className="text-[11px] text-ink-faint">{label}</p>
      <p className={`tabular mt-0.5 text-lg font-semibold ${tone}`}>{value}</p>
    </div>
  );
}
