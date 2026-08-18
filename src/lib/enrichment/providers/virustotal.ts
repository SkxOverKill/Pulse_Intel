import type { IndicatorType } from "@/generated/prisma/enums";
import { getSecret } from "@/lib/enrichment/secrets";
import {
  ProviderError,
  ProviderRateLimitError,
  providerFetch,
  verdictFromScore,
  type EnrichmentProvider,
  type LookupResult,
} from "@/lib/enrichment/types";

/**
 * VirusTotal API v3, public tier.
 *
 * 4 requests/minute, 500/day. This is the binding constraint on every bulk
 * operation in the platform: a 10,000-IOC paste takes ~20 days at this rate.
 * That is why enrichment is cache-first, deduplicated, queued by priority, and
 * why the UI quotes real ETAs.
 *
 * The 7-day TTL is deliberately long. VT verdicts move slowly, and every cache
 * hit is a request not spent.
 */

const ENDPOINTS: Partial<Record<IndicatorType, (v: string) => string>> = {
  IPV4: (v) => `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(v)}`,
  IPV6: (v) => `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(v)}`,
  DOMAIN: (v) => `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(v)}`,
  MD5: (v) => `https://www.virustotal.com/api/v3/files/${encodeURIComponent(v)}`,
  SHA1: (v) => `https://www.virustotal.com/api/v3/files/${encodeURIComponent(v)}`,
  SHA256: (v) => `https://www.virustotal.com/api/v3/files/${encodeURIComponent(v)}`,
  // URLs are addressed by an unpadded base64url of the URL itself.
  URL: (v) =>
    `https://www.virustotal.com/api/v3/urls/${Buffer.from(v)
      .toString("base64url")
      .replace(/=+$/, "")}`,
};

type VtStats = {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
};

export const virusTotalProvider: EnrichmentProvider = {
  name: "virustotal",
  label: "VirusTotal",
  quota: { perMinute: 4, perDay: 500 },
  ttlMs: 7 * 24 * 60 * 60 * 1000,

  supports(type) {
    return type in ENDPOINTS;
  },

  isConfigured() {
    return Boolean(getSecret("virustotal"));
  },

  async lookup(value, type): Promise<LookupResult> {
    const build = ENDPOINTS[type];
    if (!build) throw new ProviderError(`VirusTotal does not support ${type}`);

    const res = await providerFetch(build(value), {
      headers: { "x-apikey": getSecret("virustotal") ?? "" },
    });

    if (res.status === 429) {
      const retry = Number(res.headers.get("retry-after") ?? 60);
      throw new ProviderRateLimitError("VirusTotal quota exceeded", retry * 1000);
    }

    // 404 is a real answer: VT has never seen this indicator. That is not an
    // error, and recording it stops us asking again for a week.
    if (res.status === 404) {
      return { verdict: "UNKNOWN", score: null, raw: { notFound: true } };
    }

    if (!res.ok) {
      throw new ProviderError(`VirusTotal HTTP ${res.status}`, res.status);
    }

    const body = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: VtStats; reputation?: number } };
    };

    const stats = body.data?.attributes?.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const total =
      malicious +
      suspicious +
      (stats.harmless ?? 0) +
      (stats.undetected ?? 0) +
      (stats.timeout ?? 0);

    if (total === 0) {
      return { verdict: "UNKNOWN", score: null, raw: body };
    }

    // Suspicious counts half — a handful of "suspicious" hits is much weaker
    // evidence than the same number of outright malicious detections.
    const score = Math.round(((malicious + suspicious * 0.5) / total) * 100);

    return { verdict: verdictFromScore(score), score, raw: body };
  },
};
