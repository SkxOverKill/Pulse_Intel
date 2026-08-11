"use client";

import { useActionState } from "react";
import Link from "next/link";
import {
  Field,
  FormError,
  SubmitButton,
  TextArea,
  TextInput,
} from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import { saveScheduledReport } from "./actions";

type ScheduledReportInput = {
  id: string;
  name: string;
  description: string | null;
  schedule: string;
  enabled: boolean;
};

export function ScheduleForm({ report }: { report?: ScheduledReportInput }) {
  const [state, formAction] = useActionState<ActionResult<void>, FormData>(
    saveScheduledReport,
    { ok: true, data: undefined },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;

  return (
    <form action={formAction} className="space-y-5">
      {report ? <input type="hidden" name="id" value={report.id} /> : null}

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" name="name" errors={errors} required>
            <TextInput
              name="name"
              defaultValue={report?.name}
              required
              placeholder="Weekly intelligence summary"
            />
          </Field>

          <Field label="Schedule" name="schedule" errors={errors} hint="cron expression" required>
            <TextInput
              name="schedule"
              defaultValue={report?.schedule ?? "0 8 * * 1"}
              required
              className="font-mono"
              placeholder="0 8 * * 1"
            />
          </Field>

          <div className="sm:col-span-2">
            <Field label="Description" name="description" errors={errors}>
              <TextArea
                name="description"
                defaultValue={report?.description ?? ""}
                placeholder="What this report is for, and who reads it."
              />
            </Field>
          </div>

          <div className="sm:col-span-2">
            <label className="flex items-center gap-2 text-sm text-ink">
              <input
                type="checkbox"
                name="enabled"
                value="true"
                defaultChecked={report?.enabled ?? true}
                className="size-4 rounded border-line bg-base accent-brand"
              />
              Enabled
            </label>
          </div>
        </div>

        <p className="mt-4 border-t border-line/60 pt-3 text-xs text-ink-muted">
          Each run files a new report summarizing what changed since the last run: new
          indicators by severity, new actors/campaigns, CISA KEV additions, hunt alerts, and
          feed health. Shows up in <span className="text-ink-faint">Reports</span> with no
          author, so it reads as generated, not analyst-claimed.
        </p>
      </div>

      <FormError error={!state.ok ? state.error : undefined} />

      <div className="flex items-center gap-2">
        <SubmitButton>{report ? "Save changes" : "Create schedule"}</SubmitButton>
        <Link
          href="/reports/scheduled"
          className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          Cancel
        </Link>
      </div>
    </form>
  );
}
