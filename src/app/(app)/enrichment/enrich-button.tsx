"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { Zap } from "lucide-react";
import type { ActionResult } from "@/lib/actions";
import { enrichAllPending } from "./actions";

function Submit({ pending }: { pending: number }) {
  const { pending: submitting } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={submitting || pending === 0}
      className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-brand px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-50"
    >
      <Zap className="size-4" />
      {submitting
        ? "Queueing…"
        : pending === 0
          ? "Nothing pending"
          : `Enrich ${pending.toLocaleString()} pending`}
    </button>
  );
}

export function EnrichAllButton({ pending }: { pending: number }) {
  const [state, formAction] = useActionState<
    ActionResult<{ queued: number }>,
    FormData
  >(enrichAllPending, { ok: true, data: { queued: 0 } });

  return (
    <div className="flex flex-col items-end gap-1">
      <form action={formAction}>
        <Submit pending={pending} />
      </form>
      {state.ok && state.data.queued > 0 ? (
        <p className="text-xs text-ok">
          Queued {state.data.queued.toLocaleString()} jobs — the worker will drain
          them within provider quotas.
        </p>
      ) : null}
      {!state.ok ? <p className="text-xs text-danger">{state.error}</p> : null}
    </div>
  );
}
