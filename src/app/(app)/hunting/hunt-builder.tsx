"use client";

import { useActionState, useState } from "react";
import Link from "next/link";
import { Plus, Trash2 } from "lucide-react";
import {
  Field,
  FormError,
  Select,
  SubmitButton,
  TextArea,
  TextInput,
} from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import {
  HUNT_FIELDS,
  OPERATOR_LABELS,
  describeHunt,
  fieldDef,
  type Condition,
  type HuntMatch,
  type HuntQueryAst,
  type Operator,
} from "@/lib/hunting/schema";
import {
  DETECTION_LANGUAGES,
  compileDetectionQuery,
  type DetectionLanguage,
} from "@/lib/hunting/detections";
import { saveHunt } from "./actions";

type HuntInput = {
  id: string;
  name: string;
  description: string | null;
  schedule: string | null;
  notifyOnHit: boolean;
  ast: HuntQueryAst;
};

type Row = { field: string; op: Operator; value: string | string[] };

/** A fresh row defaults to the first field and its first operator. */
function blankRow(): Row {
  const def = HUNT_FIELDS[0];
  return { field: def.key, op: def.ops[0], value: def.options?.[0] ?? "" };
}

/** A sensible default value when the field or operator changes shape. */
function defaultValueFor(field: string, op: Operator): string | string[] {
  if (op === "in") return [];
  const def = fieldDef(field);
  if (def?.type === "enum") return def.options?.[0] ?? "";
  return "";
}

export function HuntBuilder({
  hunt,
  sources,
}: {
  hunt?: HuntInput;
  sources: { id: string; name: string }[];
}) {
  const [state, formAction] = useActionState<ActionResult<void>, FormData>(
    saveHunt,
    { ok: true, data: undefined },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;

  const [match, setMatch] = useState<HuntMatch>(hunt?.ast.match ?? "all");
  const [detectionLanguage, setDetectionLanguage] =
    useState<DetectionLanguage>("kql");
  const [rows, setRows] = useState<Row[]>(
    hunt?.ast.conditions.length
      ? hunt.ast.conditions.map((c) => ({ field: c.field, op: c.op, value: c.value }))
      : [blankRow()],
  );

  function updateRow(i: number, patch: Partial<Row>) {
    setRows((prev) =>
      prev.map((r, idx) => {
        if (idx !== i) return r;
        const next = { ...r, ...patch };
        // Field changed: snap the operator to one this field supports, and
        // reset the value to match the new field's shape.
        if (patch.field && patch.field !== r.field) {
          const def = fieldDef(patch.field);
          next.op = def?.ops[0] ?? "eq";
          next.value = defaultValueFor(patch.field, next.op);
        } else if (patch.op && patch.op !== r.op) {
          next.value = defaultValueFor(next.field, patch.op);
        }
        return next;
      }),
    );
  }

  const conditions: Condition[] = rows.map((r) => ({
    field: r.field,
    op: r.op,
    value: r.value,
  }));
  const ast: HuntQueryAst = { entity: "indicator", match, conditions };
  const queryJson = JSON.stringify(ast);
  const detectionQuery = compileDetectionQuery(ast, detectionLanguage);

  return (
    <form action={formAction} className="space-y-5">
      {hunt ? <input type="hidden" name="id" value={hunt.id} /> : null}
      <input type="hidden" name="query" value={queryJson} />

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" name="name" errors={errors} required>
            <TextInput
              name="name"
              defaultValue={hunt?.name}
              required
              placeholder="New high-severity C2 IPs"
            />
          </Field>

          <Field
            label="Schedule"
            name="schedule"
            errors={errors}
            hint="cron — blank runs only on demand"
          >
            <TextInput
              name="schedule"
              defaultValue={hunt?.schedule ?? ""}
              placeholder="0 * * * *"
              className="font-mono"
            />
          </Field>

          <div className="sm:col-span-2">
            <Field label="Description" name="description" errors={errors}>
              <TextArea
                name="description"
                defaultValue={hunt?.description ?? ""}
                placeholder="What is this hunt looking for, and why?"
              />
            </Field>
          </div>
        </div>
      </div>

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-ink">Conditions</h2>
          <label className="flex items-center gap-2 text-xs text-ink-muted">
            Match
            <select
              value={match}
              onChange={(e) => setMatch(e.target.value as HuntMatch)}
              className="rounded-md border border-line bg-base px-2 py-1 text-xs text-ink focus:border-brand focus:outline-none"
            >
              <option value="all">all conditions (AND)</option>
              <option value="any">any condition (OR)</option>
            </select>
          </label>
        </div>

        <div className="space-y-2">
          {rows.map((row, i) => (
            <ConditionRow
              key={i}
              row={row}
              sources={sources}
              onChange={(patch) => updateRow(i, patch)}
              onRemove={rows.length > 1 ? () => setRows((p) => p.filter((_, idx) => idx !== i)) : undefined}
            />
          ))}
        </div>

        <button
          type="button"
          onClick={() => setRows((p) => [...p, blankRow()])}
          className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-1.5 text-xs text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          <Plus className="size-3.5" />
          Add condition
        </button>

        <p className="mt-4 border-t border-line/60 pt-3 text-xs text-ink-muted">
          <span className="text-ink-faint">Reads as: </span>
          {conditions.length ? describeHunt(ast) : "no conditions yet"}
        </p>
      </div>

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-ink">Detection query</h2>
          <div className="flex rounded-md border border-line bg-base p-0.5">
            {DETECTION_LANGUAGES.map((language) => (
              <button
                key={language.id}
                type="button"
                onClick={() => setDetectionLanguage(language.id)}
                className={
                  "rounded px-2.5 py-1 text-xs transition-colors " +
                  (detectionLanguage === language.id
                    ? "bg-surface-2 text-ink"
                    : "text-ink-muted hover:text-ink")
                }
              >
                {language.label}
              </button>
            ))}
          </div>
        </div>
        <textarea
          readOnly
          value={detectionQuery}
          className="min-h-28 w-full resize-y rounded-md border border-line bg-base p-3 font-mono text-xs text-ink outline-none"
        />
      </div>

      <div className="rounded-[--radius-card] border border-line bg-surface p-5">
        <label className="flex items-start gap-2.5 text-sm text-ink">
          <input
            type="checkbox"
            name="notifyOnHit"
            value="true"
            defaultChecked={hunt?.notifyOnHit ?? false}
            className="mt-0.5 size-4 rounded border-line bg-base accent-brand"
          />
          <span>
            Alert on new matches
            <span className="mt-0.5 block text-xs text-ink-muted">
              When scheduled, raise an alert if a run finds indicators that weren&apos;t
              there last time. Whitelisted indicators are never alerted on.
            </span>
          </span>
        </label>
      </div>

      <FormError error={!state.ok ? state.error : undefined} />

      <div className="flex items-center gap-2">
        <SubmitButton>{hunt ? "Save changes" : "Create hunt"}</SubmitButton>
        <Link
          href={hunt ? `/hunting/${hunt.id}` : "/hunting"}
          className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          Cancel
        </Link>
      </div>
    </form>
  );
}

function ConditionRow({
  row,
  sources,
  onChange,
  onRemove,
}: {
  row: Row;
  sources: { id: string; name: string }[];
  onChange: (patch: Partial<Row>) => void;
  onRemove?: () => void;
}) {
  const def = fieldDef(row.field);

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-line/60 bg-base/40 p-2">
      <Select
        aria-label="Field"
        value={row.field}
        onChange={(e) => onChange({ field: e.target.value })}
        options={HUNT_FIELDS.map((f) => ({ value: f.key, label: f.label }))}
        className="w-36"
      />
      <Select
        aria-label="Operator"
        value={row.op}
        onChange={(e) => onChange({ op: e.target.value as Operator })}
        options={(def?.ops ?? []).map((o) => ({ value: o, label: OPERATOR_LABELS[o] }))}
        className="w-32"
      />

      <ValueControl row={row} def={def} sources={sources} onChange={onChange} />

      {onRemove ? (
        <button
          type="button"
          onClick={onRemove}
          aria-label="Remove condition"
          className="ml-auto grid size-7 place-items-center rounded text-ink-faint hover:bg-surface-2 hover:text-danger"
        >
          <Trash2 className="size-3.5" />
        </button>
      ) : null}
    </div>
  );
}

function ValueControl({
  row,
  def,
  sources,
  onChange,
}: {
  row: Row;
  def: ReturnType<typeof fieldDef>;
  sources: { id: string; name: string }[];
  onChange: (patch: Partial<Row>) => void;
}) {
  if (!def) return null;

  // Multi-select for `in`: a compact checkbox group over the enum options.
  if (row.op === "in" && def.options) {
    const selected = Array.isArray(row.value) ? row.value : [];
    return (
      <div className="flex flex-1 flex-wrap gap-1.5">
        {def.options.map((opt) => {
          const on = selected.includes(opt);
          return (
            <button
              key={opt}
              type="button"
              onClick={() =>
                onChange({
                  value: on
                    ? selected.filter((v) => v !== opt)
                    : [...selected, opt],
                })
              }
              className={
                "rounded border px-1.5 py-0.5 text-[11px] font-medium transition-colors " +
                (on
                  ? "border-brand/50 bg-brand/15 text-ink"
                  : "border-line bg-surface-2 text-ink-faint hover:text-ink-muted")
              }
            >
              {opt}
            </button>
          );
        })}
      </div>
    );
  }

  const scalar = Array.isArray(row.value) ? "" : row.value;

  if (def.type === "enum" && def.options) {
    return (
      <Select
        aria-label="Value"
        value={scalar}
        onChange={(e) => onChange({ value: e.target.value })}
        options={def.options.map((o) => ({ value: o, label: o }))}
        className="w-40"
      />
    );
  }

  if (def.type === "source") {
    return (
      <Select
        aria-label="Value"
        value={scalar}
        onChange={(e) => onChange({ value: e.target.value })}
        options={[
          { value: "", label: sources.length ? "Select a source…" : "No sources" },
          ...sources.map((s) => ({ value: s.id, label: s.name })),
        ]}
        className="w-52"
      />
    );
  }

  if (def.type === "number") {
    return (
      <TextInput
        aria-label="Value"
        type="number"
        min={0}
        max={100}
        value={scalar}
        onChange={(e) => onChange({ value: e.target.value })}
        placeholder={def.hint}
        className="w-28"
      />
    );
  }

  if (def.type === "date") {
    return (
      <TextInput
        aria-label="Value"
        type="date"
        value={scalar}
        onChange={(e) => onChange({ value: e.target.value })}
        className="w-44"
      />
    );
  }

  // text, tag
  return (
    <TextInput
      aria-label="Value"
      value={scalar}
      onChange={(e) => onChange({ value: e.target.value })}
      placeholder={def.type === "tag" ? "ransomware" : def.hint}
      className="min-w-40 flex-1"
    />
  );
}
