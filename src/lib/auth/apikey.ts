/**
 * API key generation and hashing for the public REST API.
 *
 * Pure crypto, no `db` import — kept separate from `src/lib/api/auth.ts` (which
 * does the lookup) so this half is trivially unit-testable and the storage
 * shape can't leak into the hashing logic.
 *
 * Mirrors the session token design in `auth/session.ts`: only a SHA-256 hash is
 * stored (`ApiKey.keyHash`), so a database dump does not yield usable keys. The
 * raw key exists only at creation time, shown once, never persisted.
 */
// No `server-only` marker, deliberately: this is pure crypto with no request-
// scoped API, and both the unit tests and scripts/verify-api.ts import it
// through plain Node (no bundler), which is exactly where `server-only` throws.
import { createHash, randomBytes } from "node:crypto";

/** Shown once at creation, then only `prefix` is ever displayed again. */
const PREFIX_CHAR_COUNT = 10;

export type GeneratedApiKey = {
  /** The full secret. Return to the caller once; never store it. */
  raw: string;
  /** First few characters of the secret, safe to store and display for lookup. */
  prefix: string;
  /** SHA-256 hex digest of `raw`. This is what gets stored. */
  hash: string;
};

export function generateApiKey(): GeneratedApiKey {
  // "pulse_" makes a leaked key greppable/identifiable in logs and secret
  // scanners, the same reason GitHub/Stripe-style tokens are prefixed.
  const raw = `pulse_${randomBytes(24).toString("base64url")}`;
  return {
    raw,
    prefix: raw.slice(0, PREFIX_CHAR_COUNT),
    hash: hashApiKey(raw),
  };
}

export function hashApiKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

/** Extracts the raw key from an `Authorization: Bearer <key>` header value. */
export function parseBearerToken(header: string | null): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1] : null;
}
