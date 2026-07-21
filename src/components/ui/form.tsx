"use client";

import type { ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";

const CONTROL =
  "w-full rounded-md border border-line bg-base px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none disabled:opacity-60";

export function Field({
  label,
  name,
  hint,
  errors,
  required,
  children,
}: {
  label: string;
  name: string;
  hint?: string;
  errors?: Record<string, string[]>;
  required?: boolean;
  children: ReactNode;
}) {
  const fieldErrors = errors?.[name];
  return (
    <div>
      <label htmlFor={name} className="mb-1.5 flex items-baseline gap-1.5 text-xs font-medium text-ink-muted">
        {label}
        {required ? <span className="text-danger">*</span> : null}
        {hint ? <span className="font-normal text-ink-faint">— {hint}</span> : null}
      </label>
      {children}
      {fieldErrors?.length ? (
        <p className="mt-1 text-xs text-danger">{fieldErrors[0]}</p>
      ) : null}
    </div>
  );
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} id={props.id ?? props.name} className={cn(CONTROL, props.className)} />;
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      id={props.id ?? props.name}
      className={cn(CONTROL, "min-h-24 resize-y", props.className)}
    />
  );
}

export function Select({
  options,
  ...props
}: React.SelectHTMLAttributes<HTMLSelectElement> & {
  options: { value: string; label: string }[];
}) {
  return (
    <select {...props} id={props.id ?? props.name} className={cn(CONTROL, props.className)}>
      {options.map((o) => (
        <option key={o.value} value={o.value} className="bg-surface">
          {o.label}
        </option>
      ))}
    </select>
  );
}

/**
 * Confidence is a first-class input everywhere in this app, so it gets a
 * dedicated control rather than a bare number field — it should read as a
 * judgement call, not a measurement.
 */
export function ConfidenceInput({
  name = "confidence",
  defaultValue = 50,
}: {
  name?: string;
  defaultValue?: number;
}) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="range"
        id={name}
        name={name}
        min={0}
        max={100}
        step={5}
        defaultValue={defaultValue}
        className="h-1.5 flex-1 cursor-pointer appearance-none rounded-full bg-surface-3 accent-brand"
        onInput={(e) => {
          const out = e.currentTarget.nextElementSibling;
          if (out) out.textContent = `${e.currentTarget.value}%`;
        }}
      />
      <output className="tabular w-10 text-right text-sm text-ink-muted">
        {defaultValue}%
      </output>
    </div>
  );
}

export function FormError({ error }: { error?: string }) {
  if (!error) return null;
  return (
    <p
      role="alert"
      className="flex items-start gap-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger"
    >
      <AlertCircle className="mt-px size-3.5 shrink-0" />
      {error}
    </p>
  );
}

export function SubmitButton({
  children = "Save",
  variant = "primary",
}: {
  children?: ReactNode;
  variant?: "primary" | "danger";
}) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className={cn(
        "rounded-md px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60",
        variant === "primary"
          ? "bg-brand text-white hover:bg-brand-hover"
          : "bg-danger text-white hover:bg-danger/85",
      )}
    >
      {pending ? "Saving…" : children}
    </button>
  );
}
