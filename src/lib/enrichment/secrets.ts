import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { db } from "@/lib/db";

/**
 * Provider credentials stored in the database.
 *
 * Keys live encrypted at rest (AES-256-GCM, keyed by `CREDENTIAL_ENC_KEY`) and
 * are served to the rest of the codebase through a *sync* resolver. The sync
 * contract matters: `EnrichmentProvider.isConfigured()` and `quota` are
 * synchronous and called by server components and the worker alike, so the
 * decrypted key must be readable without an `await`.
 *
 * Resolution order is explicit: a key set in the Settings UI (DB) wins over
 * the same key in the environment. Env is the fallback for deployments that
 * prefer env vars, and for the `ABUSEIPDB_API_KEYS` comma-list which the DB
 * path also honours on the primary `abuseipdb` row.
 *
 * This module is intentionally NOT `server-only`: the worker imports it too.
 * Each process (Next dev server, worker) keeps its own in-memory cache, so
 * both hydrate at boot; the worker also re-hydrates on its 5-minute schedule
 * sync so UI edits land without a restart.
 *
 * The DB is not touchable from here when tests run — `loadCredentialCache`
 * accepts rows so pure logic is testable without Postgres.
 */

const ALGO = "aes-256-gcm";
const IV_LEN = 12;

/** Providers whose key can be stored via the Settings UI. */
export const CREDENTIAL_PROVIDERS = [
  "virustotal",
  "otx",
  "abuseipdb",
  "shodan",
  "greynoise",
  "nvd",
] as const;

export type CredentialProvider = (typeof CREDENTIAL_PROVIDERS)[number];

/** Env vars each provider falls back to, in priority order. */
const ENV_VARS: Record<CredentialProvider, readonly string[]> = {
  virustotal: ["VIRUSTOTAL_API_KEY"],
  otx: ["OTX_API_KEY"],
  // Multi-key rotation list first, single key second — same precedence the
  // old module-level loadKeys() used.
  abuseipdb: ["ABUSEIPDB_API_KEYS", "ABUSEIPDB_API_KEY"],
  shodan: ["SHODAN_API_KEY"],
  greynoise: ["GREYNOISE_API_KEY"],
  nvd: ["NVD_API_KEY"],
};

export type CredentialOrigin = "db" | "env" | "none";

export type CredentialMeta = {
  provider: CredentialProvider;
  label: string;
  /** Primary env var name, shown in the UI as the non-DB source. */
  envVar: string;
  hint: string;
};

/** UI catalogue — labels/hints live here so the settings page stays dumb. */
export const CREDENTIAL_CATALOG: readonly CredentialMeta[] = [
  {
    provider: "virustotal",
    label: "VirusTotal",
    envVar: "VIRUSTOTAL_API_KEY",
    hint: "4 req/min, 500/day free tier — the binding constraint on bulk work.",
  },
  {
    provider: "otx",
    label: "AlienVault OTX",
    envVar: "OTX_API_KEY",
    hint: "Effectively unlimited free tier. Also powers the OTX pulses feed.",
  },
  {
    provider: "abuseipdb",
    label: "AbuseIPDB",
    envVar: "ABUSEIPDB_API_KEY",
    hint: "1,000 checks/day free tier. A comma-separated list in one field rotates keys.",
  },
  {
    provider: "shodan",
    label: "Shodan",
    envVar: "SHODAN_API_KEY",
    hint: "Optional — unlocks /shodan/host/:ip. InternetDB works without a key.",
  },
  {
    provider: "greynoise",
    label: "GreyNoise",
    envVar: "GREYNOISE_API_KEY",
    hint: "Optional — upgrades to the full /v2/noise/quick endpoint. Community tier needs none.",
  },
  {
    provider: "nvd",
    label: "NVD",
    envVar: "NVD_API_KEY",
    hint: "Raises the CVE feed from 5/rolling-30s to 50. Not required.",
  },
];

// --- Encryption ------------------------------------------------------------

/**
 * The CREDENTIAL_ENC_KEY string. Accepts either the base64 form (32 bytes) or
 * a raw passphrase, which is hashed to 32 bytes. Read lazily so tests can set
 * process.env and so a typo surfaces at first use, not at import.
 */
function encryptionKey(): Buffer {
  const raw = process.env.CREDENTIAL_ENC_KEY;
  if (!raw) {
    throw new Error(
      "CREDENTIAL_ENC_KEY is not set. Add it to .env — provider keys set in " +
        "Settings cannot be decrypted without it.",
    );
  }
  const decoded = Buffer.from(raw, "base64");
  if (decoded.length === 32) return decoded;
  // Not a 32-byte base64 blob → treat as a passphrase and derive a stable key.
  return createHash("sha256").update(raw, "utf8").digest();
}

/** Payload format: base64(iv).base64(authTag).base64(ciphertext). */
export function encryptSecret(plaintext: string): string {
  const key = encryptionKey();
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map((b) => b.toString("base64")).join(".");
}

/** Throws on a bad key, tampered payload, or malformed format. */
export function decryptSecret(payload: string): string {
  const parts = payload.split(".");
  if (parts.length !== 3) throw new Error("malformed credential payload");
  const [ivB64, tagB64, ctB64] = parts;
  const decipher = createDecipheriv(ALGO, encryptionKey(), Buffer.from(ivB64!, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64!, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(ctB64!, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

// --- Sync cache ------------------------------------------------------------

type CredentialCache = Map<string, string>;

const GLOBAL_KEY = "__pulseCredentialCache";

/** Global-scoped so Next.js HMR doesn't clone the cache on every hot reload. */
function currentCache(): CredentialCache | undefined {
  return (globalThis as Record<string, unknown>)[GLOBAL_KEY] as
    | CredentialCache
    | undefined;
}

function setCache(next: CredentialCache | undefined): void {
  (globalThis as Record<string, unknown>)[GLOBAL_KEY] = next;
}

/**
 * Loads decrypted credentials into the process cache. `rows` is injectable so
 * tests can seed the cache without a database; when omitted, the DB is read.
 */
export async function loadCredentialCache(
  rows?: { provider: string; encValue: string }[],
): Promise<void> {
  const source =
    rows ?? (await db.providerCredential.findMany({ select: { provider: true, encValue: true } }));

  const fresh = new Map<string, string>();
  for (const row of source) {
    try {
      fresh.set(row.provider, decryptSecret(row.encValue));
    } catch (err) {
      // A key that no longer decrypts (rotated CREDENTIAL_ENC_KEY, bad row)
      // must not take the whole cache down — drop it and keep going.
      console.error(
        `[secrets] could not decrypt stored credential for "${row.provider}" — ignoring`,
        err,
      );
    }
  }
  setCache(fresh);
}

/** Forgets the cache so the next read re-evaluates env / requires a reload. */
export function clearCredentialCache(): void {
  setCache(undefined);
}

// --- Sync resolution -------------------------------------------------------

/**
 * DB first, then env. Cached rows were decrypted at load time, so this is a
 * plain map hit — fast enough to call from every lookup and `isConfigured()`.
 */
export function getSecret(provider: CredentialProvider): string | undefined {
  const cached = currentCache()?.get(provider);
  if (cached !== undefined) return cached;
  for (const name of ENV_VARS[provider]) {
    const value = process.env[name];
    if (value) return value;
  }
  return undefined;
}

/** Split form for comma-list credentials (AbuseIPDB multi-key rotation). */
export function getSecretList(provider: CredentialProvider): string[] {
  const raw = getSecret(provider);
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Where the effective key currently comes from — for the Settings UI. */
export function secretOrigin(provider: CredentialProvider): CredentialOrigin {
  if (currentCache()?.has(provider)) return "db";
  if (ENV_VARS[provider].some((name) => process.env[name])) return "env";
  return "none";
}
