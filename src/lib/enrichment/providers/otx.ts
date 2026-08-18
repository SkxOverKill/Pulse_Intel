import type { IndicatorType } from "@/generated/prisma/enums";
import { getSecret } from "@/lib/enrichment/secrets";
import {
  ProviderError,
  providerFetch,
  type EnrichmentProvider,
  type LookupResult,
} from "@/lib/enrichment/types";

/**
 * AlienVault OTX.
 *
 * Effectively unlimited on the free tier, which makes it the provider to try
 * *first* for any indicator it can answer — every OTX hit is a VirusTotal
 * request not spent.
 *
 * OTX has no single reputation number. What it has is pulse membership: how many
 * community threat reports reference this indicator. That is a real signal, but
 * a soft one, so the score is capped below "certainly malicious" — a busy
 * indicator in many pulses is worth attention, not an automatic block.
 */

const PATHS: Partial<Record<IndicatorType, string>> = {
  IPV4: "IPv4",
  IPV6: "IPv6",
  DOMAIN: "domain",
  URL: "url",
  MD5: "file",
  SHA1: "file",
  SHA256: "file",
};

export const otxProvider: EnrichmentProvider = {
  name: "otx",
  label: "AlienVault OTX",
  // No documented hard limit; a modest ceiling protects us from hammering them
  // during a large bulk run.
  quota: { perMinute: 60 },
  ttlMs: 3 * 24 * 60 * 60 * 1000,

  supports(type) {
    return type in PATHS;
  },

  isConfigured() {
    return Boolean(getSecret("otx"));
  },

  async lookup(value, type): Promise<LookupResult> {
    const path = PATHS[type];
    if (!path) throw new ProviderError(`OTX does not support ${type}`);

    const res = await providerFetch(
      `https://otx.alienvault.com/api/v1/indicators/${path}/${encodeURIComponent(value)}/general`,
      { headers: { "X-OTX-API-KEY": getSecret("otx") ?? "" } },
    );

    if (res.status === 404) {
      return { verdict: "UNKNOWN", score: null, raw: { notFound: true } };
    }
    if (!res.ok) {
      throw new ProviderError(`OTX HTTP ${res.status}`, res.status);
    }

    const body = (await res.json()) as {
      pulse_info?: { count?: number; pulses?: { name?: string; tags?: string[] }[] };
      validation?: unknown[];
    };

    const pulseCount = body.pulse_info?.count ?? 0;

    // OTX's `validation` array flags indicators it considers known-good
    // (whitelisted infrastructure). Honour that over pulse count.
    if (Array.isArray(body.validation) && body.validation.length > 0) {
      return { verdict: "BENIGN", score: 0, raw: body };
    }

    if (pulseCount === 0) {
      return { verdict: "UNKNOWN", score: null, raw: body };
    }

    // Saturating curve capped at 60: pulse membership is corroboration, not
    // proof, so OTX alone never returns a MALICIOUS verdict (>=70).
    const score = Math.min(60, Math.round(20 * Math.log2(pulseCount + 1)));

    return {
      verdict: score >= 30 ? "SUSPICIOUS" : "BENIGN",
      score,
      raw: body,
    };
  },
};
