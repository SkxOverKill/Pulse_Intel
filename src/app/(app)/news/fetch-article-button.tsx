"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { Download } from "lucide-react";
import type { ActionResult } from "@/lib/actions";
import { fetchArticleContent } from "./actions";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-md bg-brand px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-60"
    >
      <Download className="size-4" />
      {pending ? "Fetching…" : "Fetch full article"}
    </button>
  );
}

export function FetchArticleButton({ newsId }: { newsId: string }) {
  const [state, formAction] = useActionState<ActionResult<{ content: string }>, FormData>(
    fetchArticleContent,
    { ok: false, error: "" },
  );

  return (
    <form action={formAction} className="space-y-2">
      <input type="hidden" name="id" value={newsId} />
      <SubmitButton />
      {!state.ok && state.error ? (
        <p className="text-xs text-danger">{state.error}</p>
      ) : null}
    </form>
  );
}
