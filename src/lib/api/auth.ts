import "server-only";

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { hashApiKey, parseBearerToken } from "@/lib/auth/apikey";

/**
 * API-key authentication for the public REST API (`/api/v1/*`).
 *
 * `proxy.ts` deliberately excludes `/api` from its matcher (see its own
 * comment), so every route under `/api/v1` must authenticate itself — there is
 * no upstream gate to lean on. This is that gate: a Bearer token, hashed and
 * looked up the same way a session cookie is (see `auth/session.ts`), never
 * compared or stored in the clear.
 */

export type ApiPrincipal = {
  apiKeyId: string;
  userId: string;
  scopes: string[];
};

export type ApiAuthResult =
  | { ok: true; principal: ApiPrincipal }
  | { ok: false; response: NextResponse };

function unauthorized(message: string): ApiAuthResult {
  return {
    ok: false,
    response: NextResponse.json({ error: message }, { status: 401 }),
  };
}

/**
 * Verifies the request's Bearer token and, if `scope` is given, that the key
 * carries it. A key with an empty `scopes` array is a full-access key — the
 * common case for a personal integration key, same as most APIs' "all scopes"
 * default when none are explicitly restricted.
 */
export async function requireApiKey(
  request: Request,
  scope?: string,
): Promise<ApiAuthResult> {
  const raw = parseBearerToken(request.headers.get("authorization"));
  if (!raw) {
    return unauthorized("Missing bearer token. Send `Authorization: Bearer <key>`.");
  }

  const key = await db.apiKey.findUnique({
    where: { keyHash: hashApiKey(raw) },
    include: { user: { select: { id: true, active: true } } },
  });

  if (!key) return unauthorized("Invalid API key.");
  if (key.revoked) return unauthorized("This API key has been revoked.");
  if (key.expiresAt && key.expiresAt < new Date()) {
    return unauthorized("This API key has expired.");
  }
  // A deactivated user's keys must stop working immediately, exactly like their
  // sessions (auth/session.ts).
  if (!key.user.active) return unauthorized("This account is deactivated.");

  if (scope && key.scopes.length > 0 && !key.scopes.includes(scope)) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: `This API key does not have the "${scope}" scope.` },
        { status: 403 },
      ),
    };
  }

  // Best-effort, like audit() — a failed usage-timestamp update must not fail
  // the request it's timing.
  db.apiKey
    .update({ where: { id: key.id }, data: { lastUsedAt: new Date() } })
    .catch((err) => console.error("[api] failed to record lastUsedAt", err));

  return {
    ok: true,
    principal: { apiKeyId: key.id, userId: key.user.id, scopes: key.scopes },
  };
}
