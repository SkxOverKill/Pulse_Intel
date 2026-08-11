import "server-only";

import type * as z from "zod";
import type { Role } from "@/generated/prisma/enums";
import { hasRole, requireUser, type CurrentUser } from "@/lib/auth/dal";

/**
 * Shared wrapper for mutating Server Actions.
 *
 * Every mutation in the app needs the same three things — an authenticated user
 * of sufficient role, validated input, and an audit entry. Doing that by hand in
 * each action is how one of them eventually ships without the role check. This
 * makes the safe path the default path.
 *
 * Audit entries are written by the individual actions rather than here, because
 * only they know the entity id (often not known until after the insert) and the
 * before/after diff.
 */

export type ActionResult<T = void> =
  | { ok: true; data: T }
  | { ok: false; error: string; fieldErrors?: Record<string, string[]> };

export function ok(): ActionResult<void>;
export function ok<T>(data: T): ActionResult<T>;
export function ok<T>(data?: T): ActionResult<T | void> {
  return { ok: true, data: data as T };
}

export function fail(
  error: string,
  fieldErrors?: Record<string, string[]>,
): ActionResult<never> {
  return { ok: false, error, fieldErrors };
}

/**
 * Validates `formData` against `schema` and runs `handler` with the parsed input
 * and the current user, provided they hold at least `role`.
 */
export async function withAction<S extends z.ZodType, T>(
  opts: {
    role: Role;
    schema: S;
    formData: FormData;
  },
  handler: (input: z.infer<S>, user: CurrentUser) => Promise<ActionResult<T>>,
): Promise<ActionResult<T>> {
  const user = await requireUser();

  if (!hasRole(user, opts.role)) {
    return fail("You do not have permission to perform this action.");
  }

  // Multi-value fields (checkbox groups, tag inputs) must survive as arrays.
  const raw: Record<string, unknown> = {};
  for (const key of new Set(opts.formData.keys())) {
    const values = opts.formData.getAll(key);
    raw[key] = values.length > 1 ? values : values[0];
  }

  const parsed = opts.schema.safeParse(raw);
  if (!parsed.success) {
    const fieldErrors: Record<string, string[]> = {};
    for (const issue of parsed.error.issues) {
      const path = issue.path.join(".") || "_";
      (fieldErrors[path] ??= []).push(issue.message);
    }
    return fail("Please correct the highlighted fields.", fieldErrors);
  }

  try {
    return await handler(parsed.data, user);
  } catch (err) {
    // Unique-constraint violations are the common, user-correctable failure;
    // surface them as such instead of a generic error.
    if (isUniqueViolation(err)) {
      return fail("That already exists — pick a different name or value.");
    }
    console.error("[action] unhandled error", err);
    return fail("Something went wrong. Check the server log.");
  }
}

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code?: string }).code === "P2002"
  );
}

/** Comma/newline separated text input to a clean string array. */
export function parseList(input: unknown): string[] {
  if (Array.isArray(input)) return input.map(String).map((s) => s.trim()).filter(Boolean);
  if (typeof input !== "string") return [];
  return input
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
