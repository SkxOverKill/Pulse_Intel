import { db } from "@/lib/db";
import { consumeToken } from "@/lib/enrichment/limiter";
import { getProvider, providersFor } from "@/lib/enrichment/registry";
import { ProviderRateLimitError } from "@/lib/enrichment/types";

/**
 * Enrichment orchestration: cache-first, quota-aware, never throwing away work.
 *
 * The ordering discipline here is what keeps the platform inside free tiers:
 *   1. a fresh cached result short-circuits before any quota is touched,
 *   2. the limiter is consulted *before* the HTTP call, not after a 429,
 *   3. a quota refusal is reported, not retried in a spin loop.
 */

export type EnrichOutcome =
  | { status: "cached"; provider: string }
  | { status: "fetched"; provider: string; verdict: string; score: number | null }
  | { status: "rate_limited"; provider: string; retryAfterMs: number; reason: string }
  | { status: "skipped"; provider: string; reason: string }
  | { status: "error"; provider: string; message: string };

/** Enrich one indicator with one provider. */
export async function enrichOne(
  indicatorId: string,
  providerName: string,
  opts: { force?: boolean } = {},
): Promise<EnrichOutcome> {
  const provider = getProvider(providerName);
  if (!provider) {
    return { status: "skipped", provider: providerName, reason: "Unknown provider" };
  }
  if (!provider.isConfigured()) {
    return { status: "skipped", provider: providerName, reason: "No API key configured" };
  }

  const indicator = await db.indicator.findUnique({ where: { id: indicatorId } });
  if (!indicator) {
    return { status: "skipped", provider: providerName, reason: "Indicator not found" };
  }
  if (!provider.supports(indicator.type)) {
    return {
      status: "skipped",
      provider: providerName,
      reason: `Does not support ${indicator.type}`,
    };
  }
  // Whitelisted indicators are known-good infrastructure. Spending scarce
  // VirusTotal quota confirming that 8.8.8.8 is Google would be absurd.
  if (indicator.whitelisted) {
    return { status: "skipped", provider: providerName, reason: "Whitelisted" };
  }

  if (!opts.force) {
    const cached = await db.enrichment.findUnique({
      where: {
        indicatorId_provider: { indicatorId, provider: provider.name },
      },
    });
    if (cached && cached.expiresAt > new Date()) {
      return { status: "cached", provider: provider.name };
    }
  }

  const decision = await consumeToken(provider.name, provider.quota);
  if (!decision.allowed) {
    return {
      status: "rate_limited",
      provider: provider.name,
      retryAfterMs: decision.retryAfterMs,
      reason: decision.reason,
    };
  }

  try {
    const result = await provider.lookup(indicator.normalizedValue, indicator.type);
    const expiresAt = new Date(Date.now() + provider.ttlMs);

    await db.enrichment.upsert({
      where: { indicatorId_provider: { indicatorId, provider: provider.name } },
      update: {
        rawResponse: result.raw as never,
        verdict: result.verdict,
        score: result.score,
        fetchedAt: new Date(),
        expiresAt,
        error: null,
      },
      create: {
        indicatorId,
        provider: provider.name,
        rawResponse: result.raw as never,
        verdict: result.verdict,
        score: result.score,
        expiresAt,
      },
    });

    return {
      status: "fetched",
      provider: provider.name,
      verdict: result.verdict,
      score: result.score,
    };
  } catch (err) {
    if (err instanceof ProviderRateLimitError) {
      return {
        status: "rate_limited",
        provider: provider.name,
        retryAfterMs: err.retryAfterMs,
        reason: "upstream",
      };
    }

    const message = err instanceof Error ? err.message : String(err);

    // Record the failure with a short TTL. Without this we cannot tell "clean"
    // from "never worked", and a permanently broken provider would be retried
    // on every single pass.
    await db.enrichment.upsert({
      where: { indicatorId_provider: { indicatorId, provider: provider.name } },
      update: {
        error: message,
        fetchedAt: new Date(),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
      create: {
        indicatorId,
        provider: provider.name,
        rawResponse: {} as never,
        verdict: "UNKNOWN",
        error: message,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
    });

    return { status: "error", provider: provider.name, message };
  }
}

/** Enrich one indicator with every provider that supports its type. */
export async function enrichAll(
  indicatorId: string,
  opts: { force?: boolean } = {},
): Promise<EnrichOutcome[]> {
  const indicator = await db.indicator.findUnique({
    where: { id: indicatorId },
    select: { type: true },
  });
  if (!indicator) return [];

  const outcomes: EnrichOutcome[] = [];
  // Sequential, in registry order: cheap providers first, and an early
  // MALICIOUS from OTX still lets the others add corroboration.
  //
  // VirusTotal is deliberately excluded from this path (single-key free tier
  // is too scarce to spend on every ingested indicator automatically) — it's
  // reserved for the analyst-triggered Lookup and Bulk lookup pages, which
  // call enrichOne() per provider directly rather than going through
  // enrichAll(). Revisit once more VirusTotal keys are added.
  for (const provider of providersFor(indicator.type).filter((p) => p.name !== "virustotal")) {
    const outcome = await enrichOne(indicatorId, provider.name, opts);
    outcomes.push(outcome);

    // OTX's own "known-good" signal (its validation list, not a low pulse
    // count) is unambiguous — the same reasoning that already lets AbuseIPDB's
    // whitelist short-circuit a check. Spending scarce VirusTotal/AbuseIPDB
    // quota re-confirming that is wasted spend, so skip the rest of the
    // (scarcer) providers for this indicator. A SUSPICIOUS/MALICIOUS-leaning
    // OTX result is deliberately NOT treated as confident here — that's
    // corroboration-worthy, not a reason to stop looking.
    if (provider.name === "otx" && outcome.status === "fetched" && outcome.score === 0) {
      break;
    }
  }
  return outcomes;
}

/**
 * Combines provider verdicts into one number for the indicator.
 * Takes the maximum rather than the mean: one provider seeing something
 * malicious is signal, and averaging it away with three "unknown"s is how real
 * detections get buried.
 */
export async function recomputeIndicatorConfidence(indicatorId: string) {
  const enrichments = await db.enrichment.findMany({
    where: { indicatorId, error: null },
    select: { score: true },
  });

  const scores = enrichments
    .map((e) => e.score)
    .filter((s): s is number => typeof s === "number");

  if (scores.length === 0) return null;

  const max = Math.max(...scores);
  await db.indicator.update({
    where: { id: indicatorId },
    data: { confidence: max },
  });
  return max;
}
