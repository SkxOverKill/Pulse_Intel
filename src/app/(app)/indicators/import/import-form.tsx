"use client";

import { useActionState } from "react";
import Link from "next/link";
import { CheckCircle2, ShieldOff, TriangleAlert } from "lucide-react";
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

const PLACEHOLDER = `8.8.8.8
evil[.]com
hxxps://bad.example.com/payload
d41d8cd98f00b204e9800998ecf8427e
CVE-2024-3400
# comments and blank lines are ignored`;

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

  const errors = !state.ok ? state.fieldErrors : undefined;
  const report = state.ok && state.data.total > 0 ? state.data : null;

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
              hint="type is detected automatically"
            >
              <TextArea
                name="text"
                required
                rows={12}
                placeholder={PLACEHOLDER}
                className="font-mono text-xs"
              />
            </Field>

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
          <SubmitButton>Import</SubmitButton>
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

/**
 * Reports every category, including the ones that mean "we did not store what
 * you pasted". Silently dropping unparseable lines is how analysts lose trust
 * in a platform.
 */
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
