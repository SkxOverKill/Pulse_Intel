"use server";

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

// Sequential + capped: a paste of thousands of lines against a 4/min, 500/day
// VirusTotal quota would just rate-limit itself into uselessness. This is an
// interactive tool an analyst is watching, not the queued bulk-enrich flow.
const MAX_LINES = 200;

export type BulkOutcome = {
  provider: string;
  label: string;
  status: "fetched" | "cached" | "rate_limited" | "skipped" | "error";
  verdict: string | null;
  score: number | null;
  detail: string | null;
  fields: Record<string, DetailValue>;
};

export type BulkRow = {
  input: string;
  indicatorId: string | null;
  type: string | null;
  value: string | null;
  whitelisted: boolean;
  error: string | null;
  outcomes: BulkOutcome[];
};

export type BulkLookupResult = {
  rows: BulkRow[];
  truncated: boolean;
};

const BulkLookupSchema = z.object({
  values: z.string().trim().min(1, { error: "Enter at least one indicator." }),
  providers: z.preprocess(
    (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]),
    z.array(z.string()).min(1, { error: "Choose at least one provider." }),
  ),
});

export async function bulkLookup(
  _prev: ActionResult<BulkLookupResult>,
  formData: FormData,
): Promise<ActionResult<BulkLookupResult>> {
  const result = await withAction(
    { role: "ANALYST", schema: BulkLookupSchema, formData },
    async (input, user) => {
      await loadCredentialCache();

      const lines = Array.from(
        new Set(
          input.values
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter(Boolean),
        ),
      );

      if (lines.length === 0) {
        return fail("Enter at least one indicator, one per line.");
      }

      const truncated = lines.length > MAX_LINES;
      const toProcess = lines.slice(0, MAX_LINES);

      const rows: BulkRow[] = [];

      for (const line of toProcess) {
        const parsedValue = parseIndicator(line);
        if (!parsedValue) {
          rows.push({
            input: line,
            indicatorId: null,
            type: null,
            value: null,
            whitelisted: false,
            error: "Unrecognized indicator format",
            outcomes: [],
          });
          continue;
        }

        await ingestText(line, { userId: user.id });
        const indicator = await db.indicator.findUnique({
          where: {
            type_normalizedValue: {
              type: parsedValue.type,
              normalizedValue: parsedValue.normalizedValue,
            },
          },
        });

        if (!indicator) {
          rows.push({
            input: line,
            indicatorId: null,
            type: parsedValue.type,
            value: null,
            whitelisted: false,
            error: "Ingest failed",
            outcomes: [],
          });
          continue;
        }

        const outcomes: BulkOutcome[] = [];
        for (const providerName of input.providers) {
          const provider = PROVIDERS.find((p) => p.name === providerName);
          const label = provider?.label ?? providerName;
          const outcome = await enrichOne(indicator.id, providerName);

          let fields: Record<string, DetailValue> = {};
          let verdict: string | null = null;
          let score: number | null = null;
          let detail: string | null = null;
          const status = outcome.status;

          if (outcome.status === "fetched" || outcome.status === "cached") {
            const row = await db.enrichment.findUnique({
              where: {
                indicatorId_provider: { indicatorId: indicator.id, provider: providerName },
              },
            });
            verdict = row?.verdict ?? null;
            score = row?.score ?? null;
            fields = extractDetails(providerName, row?.rawResponse ?? null);
          } else if (outcome.status === "rate_limited") {
            detail = `quota exhausted — retry in ${Math.ceil(outcome.retryAfterMs / 60_000)} min`;
          } else if (outcome.status === "skipped") {
            detail = outcome.reason;
          } else if (outcome.status === "error") {
            detail = outcome.message;
          }

          outcomes.push({ provider: providerName, label, status, verdict, score, detail, fields });
        }

        rows.push({
          input: line,
          indicatorId: indicator.id,
          type: indicator.type,
          value: indicator.value,
          whitelisted: indicator.whitelisted,
          error: null,
          outcomes,
        });
      }

      await audit({
        action: "ENRICH",
        entityType: "Indicator",
        userId: user.id,
        changes: { bulkLookup: true, count: toProcess.length, providers: input.providers },
      });

      return ok({ rows, truncated });
    },
  );

  return result;
}
