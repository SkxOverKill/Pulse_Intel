import type { IndicatorType, Verdict } from "@/generated/prisma/enums";
import type { QuotaConfig } from "@/lib/enrichment/limiter";

export type LookupResult = {
  verdict: Verdict;
  /** Normalized 0-100 maliciousness. Null when the provider gives no basis for one. */
  score: number | null;
  /** Raw provider response, stored as jsonb so nothing is lost in normalization. */
  raw: unknown;
};

export interface EnrichmentProvider {
  /** Stable slug — used as the Enrichment.provider value and the limiter key. */
  readonly name: string;
  readonly label: string;
  readonly quota: QuotaConfig;
  /** How long a result stays fresh. Cache-first means this directly sets spend. */
  readonly ttlMs: number;
  /** Whether this provider can say anything useful about that indicator type. */
  supports(type: IndicatorType): boolean;
  /** True when the provider has credentials and can actually run. */
  isConfigured(): boolean;
  lookup(value: string, type: IndicatorType): Promise<LookupResult>;
}

/** Thrown when a provider is rate-limited upstream despite our own limiter. */
export class ProviderRateLimitError extends Error {
  constructor(
    message: string,
    readonly retryAfterMs: number,
  ) {
    super(message);
    this.name = "ProviderRateLimitError";
  }
}

export class ProviderError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ProviderError";
  }
}

/**
 * Shared fetch with a timeout. A provider hanging for 30s would occupy a worker
 * slot and starve the queue behind it.
 */
export async function providerFetch(
  url: string,
  init: RequestInit = {},
  timeoutMs = 15_000,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Maps a 0-100 score onto a verdict using consistent thresholds. */
export function verdictFromScore(score: number): Verdict {
  if (score >= 70) return "MALICIOUS";
  if (score >= 30) return "SUSPICIOUS";
  return "BENIGN";
}
