"use client";

import { useActionState, useEffect, useRef } from "react";
import { Field, FormError, SubmitButton, TextInput } from "@/components/ui/form";
import type { ActionResult } from "@/lib/actions";
import { changePassword, type ChangePasswordState } from "./actions";

export function PasswordChangeForm() {
  const [state, formAction] = useActionState<ChangePasswordState, FormData>(
    changePassword,
    { ok: false, error: "" },
  );
  const errors = !state.ok ? state.fieldErrors : undefined;
  const formRef = useRef<HTMLFormElement>(null);

  // Clear the (filled) password fields after a successful change.
  useEffect(() => {
    if (state.ok) formRef.current?.reset();
  }, [state.ok]);

  return (
    <form ref={formRef} action={formAction} className="space-y-4">
      <Field label="Current password" name="currentPassword" required>
        <TextInput
          type="password"
          name="currentPassword"
          autoComplete="current-password"
          required
        />
      </Field>

      <Field
        label="New password"
        name="newPassword"
        hint="min 12 characters"
        errors={errors}
        required
      >
        <TextInput
          type="password"
          name="newPassword"
          autoComplete="new-password"
          required
        />
      </Field>

      <Field
        label="Confirm new password"
        name="confirmPassword"
        errors={errors}
        required
      >
        <TextInput
          type="password"
          name="confirmPassword"
          autoComplete="new-password"
          required
        />
      </Field>

      <FormError error={!state.ok ? state.error : undefined} />

      {state.ok ? (
        <p
          role="status"
          className="rounded-md border border-ok/40 bg-ok/5 px-3 py-2 text-xs text-ok"
        >
          Password updated. All other sessions were signed out.
        </p>
      ) : null}

      <div>
        <SubmitButton>Change password</SubmitButton>
      </div>
    </form>
  );
}