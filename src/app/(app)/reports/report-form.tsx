"use client";

import { useActionState } from "react";
import Link from "next/link";
import {
  ConfidenceInput,
  Field,
  FormError,
  Select,
  SubmitButton,
  TextArea,
  TextInput,
} from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import { saveReport } from "./actions";

type ReportInput = {
  id: string;
  title: string;
  summary: string | null;
  body: string;
  sourceUrl: string | null;
  tags: string[];
  tlp: string;
  confidence: number;
  published: boolean;
};

const TLPS = [
  { value: "AMBER", label: "TLP:AMBER" },
  { value: "CLEAR", label: "TLP:CLEAR" },
  { value: "GREEN", label: "TLP:GREEN" },
  { value: "AMBER_STRICT", label: "TLP:AMBER+STRICT" },
  { value: "RED", label: "TLP:RED" },
];

export function ReportForm({ report }: { report?: ReportInput }) {
  const [state, formAction] = useActionState<ActionResult<void>, FormData>(
    saveReport,
    { ok: true, data: undefined },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;

  return (
    <form action={formAction} className="space-y-5">
      {report ? <input type="hidden" name="id" value={report.id} /> : null}

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="space-y-4">
          <Field label="Title" name="title" errors={errors} required>
            <TextInput name="title" defaultValue={report?.title} required
              placeholder="QakBot resurgence targeting European manufacturing" />
          </Field>

          <Field label="Summary" name="summary" errors={errors}
            hint="one or two sentences, shown in lists and search results">
            <TextArea name="summary" rows={2} defaultValue={report?.summary ?? ""} />
          </Field>

          <Field label="Body" name="body" errors={errors} required
            hint="markdown — paste IOCs inline and extract them after saving">
            <TextArea name="body" rows={16} required defaultValue={report?.body}
              className="font-mono text-xs" />
          </Field>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Source URL" name="sourceUrl" errors={errors}
              hint="original vendor report, if any">
              <TextInput name="sourceUrl" type="url" defaultValue={report?.sourceUrl ?? ""}
                placeholder="https://vendor.example/blog/post" />
            </Field>

            <Field label="Tags" name="tags" errors={errors} hint="comma separated">
              <TextInput name="tags" defaultValue={report?.tags.join(", ") ?? ""}
                placeholder="qakbot, phishing, europe" />
            </Field>

            <Field label="TLP" name="tlp" errors={errors}>
              <Select name="tlp" options={TLPS} defaultValue={report?.tlp ?? "AMBER"} />
            </Field>

            <Field label="Confidence" name="confidence" errors={errors}>
              <ConfidenceInput defaultValue={report?.confidence ?? 50} />
            </Field>
          </div>

          <label className="flex items-center gap-2 text-sm text-ink">
            <input type="checkbox" name="published" value="true"
              defaultChecked={report?.published ?? false}
              className="size-4 rounded border-line bg-base accent-brand" />
            Published
            <span className="text-xs text-ink-faint">
              — drafts stay visible to analysts but are excluded from feeds
            </span>
          </label>
        </div>
      </div>

      <FormError error={!state.ok ? state.error : undefined} />

      <div className="flex items-center gap-2">
        <SubmitButton>{report ? "Save changes" : "Create report"}</SubmitButton>
        <Link
          href={report ? `/reports/${report.id}` : "/reports"}
          className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          Cancel
        </Link>
      </div>
    </form>
  );
}
