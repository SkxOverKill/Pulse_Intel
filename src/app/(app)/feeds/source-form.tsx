"use client";

import { useActionState } from "react";
import Link from "next/link";
import {
  ConfidenceInput,
  Field,
  FormError,
  Select,
  SubmitButton,
  TextInput,
} from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import { saveSource } from "./actions";

type SourceInput = {
  id: string;
  name: string;
  type: string;
  url: string | null;
  schedule: string | null;
  enabled: boolean;
  defaultTlp: string;
  defaultConfidence: number;
  decayHalfLifeDays: number | null;
};

const TYPES = [
  { value: "MANUAL", label: "Manual — analyst imports" },
  { value: "RSS", label: "RSS / Atom" },
  { value: "TAXII", label: "TAXII 2.1" },
  { value: "MISP", label: "MISP" },
  { value: "CSV", label: "CSV" },
  { value: "JSON", label: "JSON" },
  { value: "TEXT", label: "Plain text IOC list" },
];

const TLPS = [
  { value: "AMBER", label: "TLP:AMBER" },
  { value: "CLEAR", label: "TLP:CLEAR" },
  { value: "GREEN", label: "TLP:GREEN" },
  { value: "AMBER_STRICT", label: "TLP:AMBER+STRICT" },
  { value: "RED", label: "TLP:RED" },
];

export function SourceForm({ source }: { source?: SourceInput }) {
  const [state, formAction] = useActionState<ActionResult<void>, FormData>(
    saveSource,
    { ok: true, data: undefined },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;

  return (
    <form action={formAction} className="space-y-5">
      {source ? <input type="hidden" name="id" value={source.id} /> : null}

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" name="name" errors={errors} required>
            <TextInput name="name" defaultValue={source?.name} required
              placeholder="abuse.ch URLhaus" />
          </Field>

          <Field label="Type" name="type" errors={errors}>
            <Select name="type" options={TYPES} defaultValue={source?.type ?? "MANUAL"} />
          </Field>

          <div className="sm:col-span-2">
            <Field label="URL" name="url" errors={errors}
              hint="blank for manual-only sources">
              <TextInput name="url" type="url" defaultValue={source?.url ?? ""}
                placeholder="https://urlhaus.abuse.ch/downloads/csv_recent/" />
            </Field>
          </div>

          <Field label="Schedule" name="schedule" errors={errors}
            hint="cron expression — inert until Phase 5">
            <TextInput name="schedule" defaultValue={source?.schedule ?? ""}
              placeholder="0 */6 * * *" className="font-mono" />
          </Field>

          <Field label="Decay half-life (days)" name="decayHalfLifeDays" errors={errors}
            hint="blank = never expires">
            <TextInput name="decayHalfLifeDays" type="number" min={0} max={3650}
              defaultValue={source?.decayHalfLifeDays ?? ""} placeholder="30" />
          </Field>

          <Field label="Default TLP" name="defaultTlp" errors={errors}>
            <Select name="defaultTlp" options={TLPS}
              defaultValue={source?.defaultTlp ?? "AMBER"} />
          </Field>

          <Field label="Default confidence" name="defaultConfidence" errors={errors}
            hint="how much you trust this source by default">
            <ConfidenceInput name="defaultConfidence"
              defaultValue={source?.defaultConfidence ?? 50} />
          </Field>

          <div className="sm:col-span-2">
            <label className="flex items-center gap-2 text-sm text-ink">
              <input type="checkbox" name="enabled" value="true"
                defaultChecked={source?.enabled ?? true}
                className="size-4 rounded border-line bg-base accent-brand" />
              Enabled
            </label>
          </div>
        </div>
      </div>

      <FormError error={!state.ok ? state.error : undefined} />

      <div className="flex items-center gap-2">
        <SubmitButton>{source ? "Save changes" : "Create source"}</SubmitButton>
        <Link
          href="/feeds"
          className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          Cancel
        </Link>
      </div>
    </form>
  );
}
