"use server";

import { revalidatePath } from "next/cache";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { ok, fail, withAction, type ActionResult } from "@/lib/actions";
import { hashPassword, verifyPassword } from "@/lib/auth/password";
import { resolveSession } from "@/lib/auth/session";
import { newPasswordIssue } from "@/lib/auth/password-policy";

const ChangePasswordSchema = z
  .object({
    currentPassword: z.string().min(1, { error: "Enter your current password." }),
    newPassword: z.string(),
    confirmPassword: z.string(),
  })
  // Confirm field carries the "does not match" error so the form can highlight
  // the typo directly; the new-password field carries the length policy.
  .superRefine((val, ctx) => {
    if (val.newPassword !== val.confirmPassword) {
      ctx.addIssue({
        code: "custom",
        message: "Passwords do not match.",
        path: ["confirmPassword"],
      });
    }
    const issue = newPasswordIssue(val.newPassword, val.confirmPassword);
    if (issue && issue !== "Password confirmation does not match.") {
      ctx.addIssue({ code: "custom", message: issue, path: ["newPassword"] });
    }
  });

export type ChangePasswordState = ActionResult;

/**
 * Self-service password change. `READONLY` is the floor because *any*
 * authenticated user may change their own password — not just admins.
 *
 * Security model:
 * - The current password must verify against the stored hash, so a hijacked
 *   session cannot repoint the account without knowing its secret.
 * - The current session stays valid; every *other* session is revoked. A
 *   password change after a login from an unfamiliar device should invalidate
 *   the sessions that device holds, not the operator's own.
 * - Demo mode is rejected: the demo viewer account is shared by everyone, and
 *   a public demo should not let an anonymous visitor rotate the seed password.
 */
export async function changePassword(
  _prev: ChangePasswordState,
  formData: FormData,
): Promise<ChangePasswordState> {
  if (process.env.PULSE_DEMO_MODE === "1") {
    return fail("Password changes are disabled in demo mode.");
  }

  return withAction(
    { role: "READONLY", schema: ChangePasswordSchema, formData },
    async (input, user) => {
      const fresh = await db.user.findUnique({ where: { id: user.id } });
      if (!fresh) {
        return fail("Account not found.");
      }

      const currentOk = await verifyPassword(fresh.passwordHash, input.currentPassword);
      if (!currentOk) {
        await audit({
          action: "UPDATE",
          entityType: "User",
          entityId: user.id,
          userId: user.id,
          changes: { action: "PASSWORD_CHANGE_DENIED", reason: "wrong_current" },
        });
        return fail("Current password is incorrect.");
      }

      if (input.newPassword === input.currentPassword) {
        return fail("New password must be different from the current password.");
      }

      const session = await resolveSession();
      if (session) {
        await db.session.deleteMany({
          where: { userId: user.id, tokenHash: { not: session.tokenHash } },
        });
      }

      await db.user.update({
        where: { id: user.id },
        data: { passwordHash: await hashPassword(input.newPassword) },
      });

      await audit({
        action: "UPDATE",
        entityType: "User",
        entityId: user.id,
        userId: user.id,
        changes: { action: "PASSWORD_CHANGED" },
      });

      revalidatePath("/account/password");
      return ok();
    },
  );
}