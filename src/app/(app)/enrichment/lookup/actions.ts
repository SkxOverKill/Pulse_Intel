"use server";

import { revalidatePath } from "next/cache";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { fail, ok, withAction, type ActionResult } from "@/lib/actions";
import { parseIndicator } from "@/lib/ioc/normalize";
import { ingestText } from "@/lib/ioc/ingest";
import { enrichOne } from "@/lib/enrichment/enrich";
import { loadCredentialCache } from "@/lib/enrichment/secrets";
import { PROVIDERS } from "@/lib/enrichment/registry";
import { extractDetails, type DetailValue } from "@/lib/enrichment/details";

export type LookupOutcome = {
  provider: string;
  label: string;
  status: "fetched" | "cached" | "rate_limited" | "skipped" | "error";
  /** Populated for "fetched" and "cached" — cached carries no verdict of its
   *  own (see EnrichOutcome), so it's read back from the stored Enrichment row. */
  verdict: string | null;
  score: number | null;
  /** Human-readable detail for non-verdict statuses (why skipped, retry ETA, error). */
  detail: string | null;
  /** Every field the provider gave us beyond verdict/score — country, ISP,
   *  ASN, per-engine detection counts, etc. See lib/enrichment/details.ts. */
  fields: Record<string, DetailValue>;
};

export type LookupResult = {
  indicatorId: string;
  type: string;
  value: string;
  whitelisted: boolean;
  outcomes: LookupOutcome[];
};

const LookupSchema = z.object({
  value: z.string().trim().min(1, { error: "Enter an IOC to look up." }),
  // Same array-vs-scalar quirk as elsewhere: a single checked checkbox arrives
  // as a bare string, not a one-element array.
  providers: z.preprocess(
    (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]),
    z.array(z.string()).min(1, { error: "Choose at least one provider." }),
  ),
});

/**
 * Ad-hoc single-IOC lookup: paste anything, pick which provider(s) to ask.
 * Unlike the bulk "Enrich pending" flow, this always goes through immediately
 * (INTERACTIVE priority is implicit — it runs inline, not via the queue) since
 * an analyst is watching and waiting on one value, not a few thousand.
 *
 * Reuses the single ingest path (ioc/ingest.ts) so a looked-up IOC becomes a
 * real, deduplicated Indicator — the same row a feed would have created —
 * rather than a one-off side channel that bypasses whitelisting or dedup.
 */
export async function lookupIndicator(
  _prev: ActionResult<LookupResult>,
  formData: FormData,
): Promise<ActionResult<LookupResult>> {
  const result = await withAction(
    { role: "ANALYST", schema: LookupSchema, formData },
    async (input, user) => {
      // Keep the provider key cache warm in case this action runs before any
      // page render hydrated it (warm boot, server restart between requests).
      await loadCredentialCache();

      const parsedValue = parseIndicator(input.value);
      if (!parsedValue) {
        return fail(
          "Couldn't determine what kind of indicator that is — check the value and try again.",
        );
      }

      await ingestText(input.value, { userId: user.id });

      const indicator = await db.indicator.findUnique({
        where: {
          type_normalizedValue: {
            type: parsedValue.type,
            normalizedValue: parsedValue.normalizedValue,
          },
        },
      });
      if (!indicator) {
        return fail("Ingest succeeded but the indicator could not be found — try again.");
      }

      const outcomes: LookupOutcome[] = [];
      for (const providerName of input.providers) {
        const provider = PROVIDERS.find((p) => p.name === providerName);
        const label = provider?.label ?? providerName;
        const outcome = await enrichOne(indicator.id, providerName);

        if (outcome.status === "fetched" || outcome.status === "cached") {
          // Read the row back either way — "cached" carries no verdict of its
          // own, and this is also where the raw response for `fields` lives.
          const row = await db.enrichment.findUnique({
            where: { indicatorId_provider: { indicatorId: indicator.id, provider: providerName } },
          });
          outcomes.push({
            provider: providerName,
            label,
            status: outcome.status,
            verdict: row?.verdict ?? (outcome.status === "fetched" ? outcome.verdict : null),
            score: row?.score ?? (outcome.status === "fetched" ? outcome.score : null),
            detail: null,
            fields: extractDetails(providerName, row?.rawResponse ?? null),
          });
        } else if (outcome.status === "rate_limited") {
          outcomes.push({
            provider: providerName,
            label,
            status: "rate_limited",
            verdict: null,
            score: null,
            detail: `quota exhausted — retry in ${Math.ceil(outcome.retryAfterMs / 60_000)} min`,
            fields: {},
          });
        } else if (outcome.status === "skipped") {
          outcomes.push({
            provider: providerName,
            label,
            status: "skipped",
            verdict: null,
            score: null,
            detail: outcome.reason,
            fields: {},
          });
        } else {
          outcomes.push({
            provider: providerName,
            label,
            status: "error",
            verdict: null,
            score: null,
            detail: outcome.message,
            fields: {},
          });
        }
      }

      await audit({
        action: "ENRICH",
        entityType: "Indicator",
        entityId: indicator.id,
        userId: user.id,
        changes: { lookup: true, providers: input.providers },
      });

      return ok({
        indicatorId: indicator.id,
        type: indicator.type,
        value: indicator.value,
        whitelisted: indicator.whitelisted,
        outcomes,
      });
    },
  );

  if (result.ok) revalidatePath(`/indicators/${result.data.indicatorId}`);
  return result;
}
