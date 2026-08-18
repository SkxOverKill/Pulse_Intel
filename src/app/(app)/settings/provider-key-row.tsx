"use client";

import { useEffect, useRef } from "react";
import { useActionState } from "react";
import { useRouter } from "next/navigation";
import { FormError, SubmitButton, TextInput } from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import type { CredentialProvider, CredentialOrigin } from "@/lib/enrichment/secrets";
import { clearProviderCredential, setProviderCredential } from "./actions";

type ProviderRow = {
  provider: CredentialProvider;
  label: string;
  envVar: string;
  hint: string;
  origin: CredentialOrigin;
};

export function ProviderKeyRow({ row }: { row: ProviderRow }) {
  const [state, formAction] = useActionState<ActionResult, FormData>(setProviderCredential, {
    ok: false,
    error: "",
  });
  const formRef = useRef<HTMLFormElement>(null);
  const router = useRouter();

  useEffect(() => {
    if (state.ok) {
      // The action revalidated /settings; an explicit refresh repaints the
      // status pill (db vs env) without waiting for the next navigation.
      router.refresh();
      formRef.current?.reset();
    }
  }, [state.ok, router]);

  const status =
    row.origin === "db" ? (
      <span className="rounded-full bg-ok/10 px-2 py-px text-[11px] font-medium text-ok">
        Set in Settings
      </span>
    ) : row.origin === "env" ? (
      <span className="rounded-full bg-surface-3 px-2 py-px text-[11px] text-ink-muted">
        via {row.envVar}
      </span>
    ) : (
      <span className="rounded-full bg-surface-3 px-2 py-px text-[11px] text-ink-faint">
        not set
      </span>
    );

  return (
    <div className="flex flex-col gap-3 border-t border-line px-4 py-3 lg:flex-row lg:items-center">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-ink">{row.label}</span>
          {status}
        </div>
        <p className="mt-0.5 text-xs text-ink-faint">{row.hint}</p>
      </div>

      <div className="flex flex-col items-start gap-1.5 sm:w-72 sm:flex-row sm:items-center">
        <form ref={formRef} action={formAction} className="contents">
          <input type="hidden" name="provider" value={row.provider} />
          <TextInput
            type="password"
            name="value"
            aria-label={`${row.label} API key`}
            placeholder="Paste a new key to set or rotate"
            autoComplete="off"
            className="w-full sm:w-56"
          />
          <SubmitButton>Save</SubmitButton>
        </form>
        {row.origin === "db" ? (
          <form action={clearProviderCredential}>
            <input type="hidden" name="provider" value={row.provider} />
            <button
              type="submit"
              className="rounded-md border border-line px-3 py-2 text-xs text-ink-muted hover:border-danger/40 hover:bg-danger/10 hover:text-danger"
            >
              Clear
            </button>
          </form>
        ) : null}
        <FormError error={!state.ok ? state.error : undefined} />
      </div>
    </div>
  );
}