import "server-only";

import { cache } from "react";
import { redirect } from "next/navigation";
import type { Role } from "@/generated/prisma/enums";
import { db } from "@/lib/db";

export type CurrentUser = {
  id: string;
  email: string;
  name: string;
  role: Role;
};

/// This app is shared publicly (portfolio/demo link, no login wall) — every
/// visitor is treated as this one fixed, real seeded user rather than an
/// authenticated session. READONLY on purpose: an anonymous visitor can browse
/// every page, but every mutation (create/edit/delete, enrichment, bulk
/// actions) still goes through `withAction()`'s role check exactly as before
/// and is rejected, same as it would be for a real too-low-privilege account.
/// If this ever needs a real login again, this is the one function to revert
/// (see the previous version's session-cookie flow in git history).
const DEMO_EMAIL = "viewer@pulse.local";

export const getCurrentUser = cache(async (): Promise<CurrentUser | null> => {
  const user = await db.user.findUnique({ where: { email: DEMO_EMAIL } });
  if (!user || !user.active) return null;

  return { id: user.id, email: user.email, name: user.name, role: user.role };
});

/// Kept as a function (not a bare constant) so every call site that used to
/// gate on "is someone logged in" still reads naturally — it just no longer
/// redirects to a login page that doesn't exist anymore.
export async function requireUser(): Promise<CurrentUser> {
  const user = await getCurrentUser();
  if (!user) {
    // Only reachable if `npm run db:seed` was never run on this database.
    throw new Error(
      "No demo user found — run `npm run db:seed` to create the seed accounts.",
    );
  }
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
