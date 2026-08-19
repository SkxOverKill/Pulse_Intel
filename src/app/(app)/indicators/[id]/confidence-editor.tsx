"use client";

import { useEffect, useRef } from "react";
import { useActionState } from "react";
import { useRouter } from "next/navigation";
import { Lock, Unlock } from "lucide-react";
import { FormError, SubmitButton, TextInput } from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import { updateIndicatorConfidence } from "../actions";

/**
 * Inline confidence editor for the indicator detail page. `lock` pins the value
 * so enrichment scores cannot overwrite an analyst's call; unchecking it
 * returns control to provider scores.
 */
export function ConfidenceEditor({
  id,
  confidence,
  locked,
}: {
  id: string;
  confidence: number;
  locked: boolean;
}) {
  const [state, formAction] = useActionState<ActionResult, FormData>(
    updateIndicatorConfidence,
    { ok: false, error: "" },
  );
  const formRef = useRef<HTMLFormElement>(null);
  const router = useRouter();

  useEffect(() => {
    if (state.ok) {
      router.refresh();
      formRef.current?.reset();
    }
  }, [state.ok, router]);

  return (
    <form ref={formRef} action={formAction} className="mt-1.5 space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <input type="hidden" name="id" value={id} />
        <TextInput
          type="number"
          name="confidence"
          min={0}
          max={100}
          defaultValue={confidence}
          aria-label="Confidence"
          className="w-20"
        />
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-ink-muted">
          <input
            type="checkbox"
            name="lock"
            defaultChecked={locked}
            className="size-3.5 rounded border-line bg-base accent-brand"
          />
          {locked ? (
            <Lock className="size-3.5 text-ok" />
          ) : (
            <Unlock className="size-3.5" />
          )}
          Pin — enrichment won&apos;t override
        </label>
        <SubmitButton>Save</SubmitButton>
      </div>
      <FormError error={!state.ok ? state.error : undefined} />
    </form>
  );
}