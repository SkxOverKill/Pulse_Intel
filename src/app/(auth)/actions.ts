"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { verifyPassword } from "@/lib/auth/password";
import { createSession, destroySession, resolveSession } from "@/lib/auth/session";

const LoginSchema = z.object({
  email: z.email({ error: "Enter a valid email address." }),
  password: z.string().min(1, { error: "Enter your password." }),
  next: z.string().optional(),
});

export type LoginState = { error?: string };

export async function login(
  _prev: LoginState,
  formData: FormData,
): Promise<LoginState> {
  const parsed = LoginSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
    next: formData.get("next") ?? undefined,
  });

  if (!parsed.success) {
    return { error: parsed.error.issues[0]?.message ?? "Invalid input." };
  }

  const { email, password, next } = parsed.data;
  const user = await db.user.findUnique({ where: { email: email.toLowerCase() } });

  // Deliberately identical response for unknown user, wrong password, and
  // deactivated account — anything else lets an attacker enumerate valid emails.
  const GENERIC = { error: "Incorrect email or password." };

  if (!user) {
    await audit({ action: "LOGIN_FAILED", entityType: "User", changes: { email } });
    return GENERIC;
  }

  const ok = await verifyPassword(user.passwordHash, password);
  if (!ok || !user.active) {
    await audit({
      action: "LOGIN_FAILED",
      entityType: "User",
      entityId: user.id,
      changes: { email, reason: ok ? "inactive" : "bad_password" },
    });
    return GENERIC;
  }

  const h = await headers();
  await createSession(user.id, {
    ipAddress: h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined,
    userAgent: h.get("user-agent") ?? undefined,
  });

  await db.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await audit({ action: "LOGIN", entityType: "User", entityId: user.id, userId: user.id });

  // Only allow same-site relative paths — an open redirect here would be a
  // phishing primitive.
  const target = next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
  redirect(target);
}

export async function logout(): Promise<void> {
  const session = await resolveSession();
  if (session) {
    await audit({
      action: "LOGOUT",
      entityType: "User",
      entityId: session.userId,
      userId: session.userId,
    });
  }
  await destroySession();
  redirect("/login");
}
