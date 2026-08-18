import { getSecretList } from "@/lib/enrichment/secrets";
import {
  ProviderError,
  ProviderRateLimitError,
  providerFetch,
  verdictFromScore,
  type EnrichmentProvider,
  type LookupResult,
} from "@/lib/enrichment/types";

/**
 * AbuseIPDB API v2, free tier: 1,000 checks/day, IP addresses only.
 *
 * Its `abuseConfidenceScore` is already a 0-100 confidence, so it maps onto our
 * score directly with no invented arithmetic.
 *
 * A 1-day TTL rather than VT's 7: abuse reports are a live signal, and an IP's
 * reputation genuinely changes day to day.
 *
 * Multi-key rotation: `ABUSEIPDB_API_KEYS` is an optional comma-separated list
 * of additional free-tier keys — or one comma-separated value set in Settings.
 * Each key has its own independent 1,000/day cap
 * on AbuseIPDB's side, so N keys give roughly N*1,000/day of real quota — the
 * shared limiter's `perDay` below is sized to match, and `lookup()` rotates to
 * the next key whenever the current one 429s instead of giving up immediately.
 * Falls back to the single `ABUSEIPDB_API_KEY` when the list isn't set.
 */

// Resolved per call (not at module load) so a key set via the Settings UI
// takes effect immediately — the DB row, the ABUSEIPDB_API_KEYS comma list,
// and the single ABUSEIPDB_API_KEY env var all feed the same comma-split path.

function currentKeys(): string[] {
  return getSecretList("abuseipdb");
}

// Round-robins across keys (not always starting from key 0) so load spreads
// evenly instead of hammering the first key until it dies every day.
let nextKeyIndex = 0;

export const abuseIpDbProvider: EnrichmentProvider = {
  name: "abuseipdb",
  label: "AbuseIPDB",
  // Getter — the daily quota is sized to the *current* key count, so adding a
  // key in Settings raises capacity without a restart.
  get quota() {
    return { perDay: 1000 * Math.max(1, currentKeys().length) };
  },
  ttlMs: 24 * 60 * 60 * 1000,

  supports(type) {
    return type === "IPV4" || type === "IPV6";
  },

  isConfigured() {
    return currentKeys().length > 0;
  },

  async lookup(value): Promise<LookupResult> {
    const keys = currentKeys();
    if (keys.length === 0) {
      throw new ProviderError("AbuseIPDB is not configured");
    }

    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", value);
    url.searchParams.set("maxAgeInDays", "90");

    let lastRetryAfterMs = 3600_000;

    // Try every key at most once per lookup — a key exhausted for the day
    // should fail fast to the next one, not retry itself.
    for (let attempt = 0; attempt < keys.length; attempt++) {
      const key = keys[nextKeyIndex % keys.length]!;
      nextKeyIndex++;

      const res = await providerFetch(url.toString(), {
        headers: { Key: key, Accept: "application/json" },
      });

      if (res.status === 429) {
        const retry = Number(res.headers.get("retry-after") ?? 3600);
        lastRetryAfterMs = retry * 1000;
        continue; // this key's daily cap is spent — rotate to the next one
      }
      if (!res.ok) {
        throw new ProviderError(`AbuseIPDB HTTP ${res.status}`, res.status);
      }

      const body = (await res.json()) as {
        data?: {
          abuseConfidenceScore?: number;
          totalReports?: number;
          isWhitelisted?: boolean;
        };
      };

      const score = body.data?.abuseConfidenceScore ?? 0;

      // AbuseIPDB maintains its own whitelist of known-good infrastructure. If
      // it says whitelisted, trust that over a low report count — this is
      // exactly the 8.8.8.8 case our own whitelist also guards.
      if (body.data?.isWhitelisted) {
        return { verdict: "BENIGN", score: 0, raw: body };
      }

      return { verdict: verdictFromScore(score), score, raw: body };
    }

    // Every key hit its daily cap.
    throw new ProviderRateLimitError("AbuseIPDB quota exceeded on all keys", lastRetryAfterMs);
  },
};
