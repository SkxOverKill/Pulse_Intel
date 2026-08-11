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
import { saveActor } from "./actions";

type ActorInput = {
  id: string;
  name: string;
  description: string | null;
  attackGroupId: string | null;
  country: string | null;
  motivation: string;
  sophistication: string | null;
  tlp: string;
  confidence: number;
  active: boolean;
  targetSectors: string[];
  targetCountries: string[];
  firstSeen: Date | null;
  lastSeen: Date | null;
};

const MOTIVATIONS = [
  { value: "UNKNOWN", label: "Unknown" },
  { value: "ESPIONAGE", label: "Espionage" },
  { value: "FINANCIAL", label: "Financial" },
  { value: "HACKTIVISM", label: "Hacktivism" },
  { value: "DESTRUCTION", label: "Destruction" },
  { value: "INFORMATION_OPS", label: "Information operations" },
];

const SOPHISTICATIONS = [
  { value: "", label: "Not assessed" },
  { value: "MINIMAL", label: "Minimal" },
  { value: "INTERMEDIATE", label: "Intermediate" },
  { value: "ADVANCED", label: "Advanced" },
  { value: "EXPERT", label: "Expert" },
  { value: "STRATEGIC", label: "Strategic" },
];

const TLPS = [
  { value: "CLEAR", label: "TLP:CLEAR" },
  { value: "GREEN", label: "TLP:GREEN" },
  { value: "AMBER", label: "TLP:AMBER" },
  { value: "AMBER_STRICT", label: "TLP:AMBER+STRICT" },
  { value: "RED", label: "TLP:RED" },
];

const dateValue = (d: Date | null) => (d ? d.toISOString().slice(0, 10) : "");

export function ActorForm({ actor }: { actor?: ActorInput }) {
  const [state, formAction] = useActionState<ActionResult<void>, FormData>(
    saveActor,
    { ok: true, data: undefined },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;

  return (
    <form action={formAction} className="space-y-5">
      {actor ? <input type="hidden" name="id" value={actor.id} /> : null}

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <Field label="Name" name="name" errors={errors} required
              hint="the primary name you track this actor under">
              <TextInput name="name" defaultValue={actor?.name} required
                placeholder="APT29" />
            </Field>
          </div>

          <div className="sm:col-span-2">
            <Field label="Description" name="description" errors={errors}>
              <TextArea name="description" defaultValue={actor?.description ?? ""}
                placeholder="Who they are, what they target, notable operations…" />
            </Field>
          </div>

          <Field label="ATT&CK group ID" name="attackGroupId" errors={errors}
            hint="blank if MITRE does not track them">
            <TextInput name="attackGroupId" defaultValue={actor?.attackGroupId ?? ""}
              placeholder="G0016" />
          </Field>

          <Field label="Country of origin" name="country" errors={errors}>
            <TextInput name="country" defaultValue={actor?.country ?? ""}
              placeholder="Russia" />
          </Field>

          <Field label="Motivation" name="motivation" errors={errors}>
            <Select name="motivation" options={MOTIVATIONS}
              defaultValue={actor?.motivation ?? "UNKNOWN"} />
          </Field>

          <Field label="Sophistication" name="sophistication" errors={errors}>
            <Select name="sophistication" options={SOPHISTICATIONS}
              defaultValue={actor?.sophistication ?? ""} />
          </Field>

          <Field label="First seen" name="firstSeen" errors={errors}>
            <TextInput name="firstSeen" type="date"
              defaultValue={dateValue(actor?.firstSeen ?? null)} />
          </Field>

          <Field label="Last seen" name="lastSeen" errors={errors}>
            <TextInput name="lastSeen" type="date"
              defaultValue={dateValue(actor?.lastSeen ?? null)} />
          </Field>

          <Field label="Target sectors" name="targetSectors" errors={errors}
            hint="comma separated">
            <TextInput name="targetSectors"
              defaultValue={actor?.targetSectors.join(", ") ?? ""}
              placeholder="Government, Defense, Energy" />
          </Field>

          <Field label="Target countries" name="targetCountries" errors={errors}
            hint="comma separated">
            <TextInput name="targetCountries"
              defaultValue={actor?.targetCountries.join(", ") ?? ""}
              placeholder="United States, Germany" />
          </Field>

          <Field label="TLP" name="tlp" errors={errors}
            hint="controls who may see this record">
            <Select name="tlp" options={TLPS} defaultValue={actor?.tlp ?? "AMBER"} />
          </Field>

          <Field label="Confidence" name="confidence" errors={errors}
            hint="how sure are you this actor is real and correctly scoped">
            <ConfidenceInput defaultValue={actor?.confidence ?? 50} />
          </Field>

          <div className="sm:col-span-2">
            <label className="flex items-center gap-2 text-sm text-ink">
              <input type="checkbox" name="active" value="true"
                defaultChecked={actor?.active ?? true}
                className="size-4 rounded border-line bg-base accent-brand" />
              Currently active
            </label>
          </div>
        </div>
      </div>

      <FormError error={!state.ok ? state.error : undefined} />

      <div className="flex items-center gap-2">
        <SubmitButton>{actor ? "Save changes" : "Create actor"}</SubmitButton>
        <Link
          href={actor ? `/actors/${actor.id}` : "/actors"}
          className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          Cancel
        </Link>
      </div>
    </form>
  );
}
