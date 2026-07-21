import "server-only";

import { cache } from "react";
import { redirect } from "next/navigation";
import type { Role } from "@/generated/prisma/enums";
import { resolveSession } from "@/lib/auth/session";

export type CurrentUser = {
  id: string;
  email: string;
  name: string;
  role: Role;
};

/// Data Access Layer. `proxy.ts` only checks that a cookie exists — it is
/// explicitly not allowed to share modules or hit the database. Real verification
/// happens here, close to the data, on every request that needs it.
///
/// `cache()` dedupes this within a single render pass, so calling it in a layout
/// and three components costs one query.
export const getCurrentUser = cache(async (): Promise<CurrentUser | null> => {
  const session = await resolveSession();
  if (!session) return null;

  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name,
    role: session.user.role,
  };
});

/// Use in any page/layout that must not render for anonymous visitors.
export async function requireUser(): Promise<CurrentUser> {
  const user = await getCurrentUser();
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
