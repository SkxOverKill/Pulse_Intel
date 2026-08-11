"use client";

import { useActionState, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Check, Copy, KeyRound } from "lucide-react";
import { Field, FormError, SubmitButton, TextInput } from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import { API_SCOPES } from "@/lib/api/scopes";
import { createApiKey } from "./actions";

export function CreateKeyForm() {
  const [state, formAction] = useActionState<ActionResult<{ raw: string }>, FormData>(
    createApiKey,
    { ok: false, error: "" },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;
  const formRef = useRef<HTMLFormElement>(null);
  const router = useRouter();
  const [copied, setCopied] = useState(false);
  // Tracks the last key the user acknowledged, not just "dismissed once" — a
  // plain boolean would stay stuck true across a second successful creation
  // and hide the new key too.
  const [acknowledged, setAcknowledged] = useState<string | null>(null);

  const revealed =
    state.ok && state.data && state.data.raw !== acknowledged ? state.data.raw : null;

  useEffect(() => {
    if (revealed) formRef.current?.reset();
  }, [revealed]);

  if (revealed) {
    return (
      <div className="rounded-[--radius-card] border border-ok/40 bg-ok/5 p-5">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-ink">
          <KeyRound className="size-4 text-ok" />
          Key created — copy it now
        </div>
        <p className="mb-3 text-xs text-ink-muted">
          This is the only time the full key is shown. It is not recoverable — if it&apos;s
          lost, revoke it and create a new one.
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded-md border border-line bg-base px-3 py-2 font-mono text-xs text-ink">
            {revealed}
          </code>
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard.writeText(revealed);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            }}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink hover:bg-surface-2"
          >
            {copied ? <Check className="size-4 text-ok" /> : <Copy className="size-4" />}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <button
          type="button"
          onClick={() => {
            setAcknowledged(revealed);
            router.refresh();
          }}
          className="mt-3 text-xs text-ink-muted underline decoration-dotted hover:text-ink"
        >
          Done — create another
        </button>
      </div>
    );
  }

  return (
    <form ref={formRef} action={formAction} className="rounded-[--radius-card] border border-line bg-surface p-5">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" name="name" errors={errors} required>
          <TextInput name="name" required placeholder="CI pipeline, SOAR integration…" />
        </Field>

        <div>
          <p className="mb-1.5 text-xs font-medium text-ink-muted">Scopes</p>
          <div className="flex flex-wrap gap-3 pt-1.5">
            {API_SCOPES.map((s) => (
              <label key={s.value} className="flex items-center gap-1.5 text-sm text-ink">
                <input
                  type="checkbox"
                  name="scopes"
                  value={s.value}
                  className="size-4 rounded border-line bg-base accent-brand"
                />
                {s.label}
              </label>
            ))}
          </div>
          <p className="mt-1.5 text-xs text-ink-faint">None checked = full access.</p>
        </div>
      </div>

      <FormError error={!state.ok ? state.error : undefined} />

      <div className="mt-4">
        <SubmitButton>Create key</SubmitButton>
      </div>
    </form>
  );
}
