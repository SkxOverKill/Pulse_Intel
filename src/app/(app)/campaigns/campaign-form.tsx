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
import { saveCampaign } from "./actions";

type CampaignInput = {
  id: string;
  name: string;
  description: string | null;
  status: string;
  startDate: Date | null;
  endDate: Date | null;
  targetSectors: string[];
  targetCountries: string[];
  tlp: string;
  confidence: number;
};

const STATUSES = [
  { value: "SUSPECTED", label: "Suspected" },
  { value: "ACTIVE", label: "Active" },
  { value: "DORMANT", label: "Dormant" },
  { value: "CONCLUDED", label: "Concluded" },
];

const TLPS = [
  { value: "AMBER", label: "TLP:AMBER" },
  { value: "CLEAR", label: "TLP:CLEAR" },
  { value: "GREEN", label: "TLP:GREEN" },
  { value: "AMBER_STRICT", label: "TLP:AMBER+STRICT" },
  { value: "RED", label: "TLP:RED" },
];

const dateValue = (d: Date | null) => (d ? d.toISOString().slice(0, 10) : "");

export function CampaignForm({ campaign }: { campaign?: CampaignInput }) {
  const [state, formAction] = useActionState<ActionResult<void>, FormData>(
    saveCampaign,
    { ok: true, data: undefined },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;

  return (
    <form action={formAction} className="space-y-5">
      {campaign ? <input type="hidden" name="id" value={campaign.id} /> : null}

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <Field label="Name" name="name" errors={errors} required>
              <TextInput name="name" defaultValue={campaign?.name} required
                placeholder="Operation Cloud Hopper" />
            </Field>
          </div>

          <div className="sm:col-span-2">
            <Field label="Description" name="description" errors={errors}>
              <TextArea name="description" defaultValue={campaign?.description ?? ""}
                placeholder="What happened, against whom, over what period…" />
            </Field>
          </div>

          <Field label="Status" name="status" errors={errors}>
            <Select name="status" options={STATUSES}
              defaultValue={campaign?.status ?? "SUSPECTED"} />
          </Field>

          <Field label="TLP" name="tlp" errors={errors}>
            <Select name="tlp" options={TLPS} defaultValue={campaign?.tlp ?? "AMBER"} />
          </Field>

          <Field label="Start date" name="startDate" errors={errors}>
            <TextInput name="startDate" type="date"
              defaultValue={dateValue(campaign?.startDate ?? null)} />
          </Field>

          <Field label="End date" name="endDate" errors={errors}
            hint="leave blank if ongoing">
            <TextInput name="endDate" type="date"
              defaultValue={dateValue(campaign?.endDate ?? null)} />
          </Field>

          <Field label="Target sectors" name="targetSectors" errors={errors}
            hint="comma separated">
            <TextInput name="targetSectors"
              defaultValue={campaign?.targetSectors.join(", ") ?? ""}
              placeholder="Healthcare, Manufacturing" />
          </Field>

          <Field label="Target countries" name="targetCountries" errors={errors}
            hint="comma separated">
            <TextInput name="targetCountries"
              defaultValue={campaign?.targetCountries.join(", ") ?? ""}
              placeholder="Japan, United Kingdom" />
          </Field>

          <div className="sm:col-span-2">
            <Field label="Confidence" name="confidence" errors={errors}
              hint="how sure are you this is a coherent campaign, not unrelated activity">
              <ConfidenceInput defaultValue={campaign?.confidence ?? 50} />
            </Field>
          </div>
        </div>
      </div>

      <FormError error={!state.ok ? state.error : undefined} />

      <div className="flex items-center gap-2">
        <SubmitButton>{campaign ? "Save changes" : "Create campaign"}</SubmitButton>
        <Link
          href={campaign ? `/campaigns/${campaign.id}` : "/campaigns"}
          className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          Cancel
        </Link>
      </div>
    </form>
  );
}
