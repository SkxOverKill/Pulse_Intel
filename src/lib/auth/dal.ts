import "server-only";

import { cache } from "react";
import { redirect } from "next/navigation";
import type { Role } from "@/generated/prisma/enums";
import { db } from "@/lib/db";
import { resolveSession } from "@/lib/auth/session";

export type CurrentUser = {
  id: string;
  email: string;
  name: string;
  role: Role;
};

const DEMO_EMAIL = "viewer@pulse.local";

export const getCurrentUser = cache(async (): Promise<CurrentUser | null> => {
  if (process.env.PULSE_DEMO_MODE === "1") {
    const user = await db.user.findUnique({ where: { email: DEMO_EMAIL } });
    if (!user || !user.active) return null;

    return { id: user.id, email: user.email, name: user.name, role: user.role };
  }

  const session = await resolveSession();
  if (!session) return null;

  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name,
    role: session.user.role,
  };
});

export async function requireUser(): Promise<CurrentUser> {
  const user = await getCurrentUser();
  if (!user && process.env.PULSE_DEMO_MODE === "1") {
    throw new Error(
      "No demo user found — run `npm run db:seed` to create the seed accounts.",
    );
  }
  if (!user) redirect("/login");
  return user;
}

const RANK: Record<Role, number> = {
  READONLY: 0,
  ANALYST: 1,
  ADMIN: 2,
};

export function hasRole(user: CurrentUser, minimum: Role): boolean {
  return RANK[user.role] >= RANK[minimum];
}

/// Roles are hierarchical: ADMIN satisfies ANALYST, ANALYST satisfies READONLY.
///
/// Redirects rather than using Next's `forbidden()` — that API still sits behind
/// the experimental `authInterrupts` flag, and the auth layer should not depend
/// on a canary feature.
export async function requireRole(minimum: Role): Promise<CurrentUser> {
  const user = await requireUser();
  if (!hasRole(user, minimum)) redirect("/forbidden");
  return user;
}
