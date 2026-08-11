// Deliberately NOT marked `server-only`. This is shared domain logic: the Next
// app, the seed scripts, and the Phase 4/5 background worker all import it, and
// the worker is a plain Node process where `server-only` throws on import. It is
// still server-side in practice — it imports the Prisma client, which no client
// bundle can pull in.
import type { Severity, Tlp } from "@/generated/prisma/enums";
import { db } from "@/lib/db";
import { indicatorExpiresAt } from "@/lib/ioc/decay";
import { parseBulk, type ParsedIndicator } from "@/lib/ioc/normalize";
import { whitelistReason } from "@/lib/ioc/whitelist";

/**
 * The single ingest path. Bulk paste, CSV upload, feed pull and the API all
 * funnel through here so dedup, whitelisting and confidence are applied
 * identically no matter where indicators come from.
 *
 * Pipeline: parse → normalize → dedup (in-input, then against DB) →
 * whitelist-flag → persist.
 */

export type IngestOptions = {
  sourceId?: string;
  tags?: string[];
  severity?: Severity;
  tlp?: Tlp;
  confidence?: number;
  userId?: string;
};

export type IngestReport = {
  created: number;
  /** Already present — timestamps refreshed, not duplicated. */
  updated: number;
  /** Collapsed within the submitted text itself. */
  duplicatesInInput: number;
  whitelisted: number;
  unparsed: string[];
  total: number;
};

export async function ingestText(
  input: string,
  options: IngestOptions = {},
): Promise<IngestReport> {
  const { parsed, unparsed, duplicatesInInput } = parseBulk(input);
  return ingestParsed(parsed, options, { unparsed, duplicatesInInput });
}

export async function ingestParsed(
  parsed: ParsedIndicator[],
  options: IngestOptions = {},
  extra: { unparsed?: string[]; duplicatesInInput?: number } = {},
): Promise<IngestReport> {
  const report: IngestReport = {
    created: 0,
    updated: 0,
    duplicatesInInput: extra.duplicatesInInput ?? 0,
    whitelisted: 0,
    unparsed: extra.unparsed ?? [],
    total: parsed.length,
  };

  if (parsed.length === 0) return report;

  const now = new Date();
  const source =
    options.sourceId ?
      await db.source.findUnique({
        where: { id: options.sourceId },
        select: { decayHalfLifeDays: true },
      })
    : null;
  const expiresAt =
    options.sourceId ? indicatorExpiresAt(now, source?.decayHalfLifeDays) : undefined;

  // Find which of these already exist, in one query rather than N.
  const existing = await db.indicator.findMany({
    where: {
      OR: parsed.map((p) => ({
        type: p.type,
        normalizedValue: p.normalizedValue,
      })),
    },
    select: { id: true, type: true, normalizedValue: true },
  });

  const existingKeys = new Map(
    existing.map((e) => [`${e.type}:${e.normalizedValue}`, e.id]),
  );

  const toCreate: ParsedIndicator[] = [];
  const toTouch: string[] = [];

  for (const p of parsed) {
    const id = existingKeys.get(`${p.type}:${p.normalizedValue}`);
    if (id) toTouch.push(id);
    else toCreate.push(p);
  }

  if (toCreate.length) {
    const rows = toCreate.map((p) => {
      const reason = whitelistReason(p.type, p.normalizedValue);
      if (reason) report.whitelisted++;
      return {
        type: p.type,
        value: p.value,
        normalizedValue: p.normalizedValue,
        firstSeen: now,
        lastSeen: now,
        confidence: options.confidence ?? 50,
        severity: options.severity ?? ("MEDIUM" as Severity),
        tlp: options.tlp ?? ("AMBER" as Tlp),
        tags: options.tags ?? [],
        sourceId: options.sourceId ?? null,
        whitelisted: Boolean(reason),
        expiresAt: expiresAt ?? null,
      };
    });

    // skipDuplicates guards the race where the same indicator is ingested
    // concurrently by a feed and an analyst between our SELECT and INSERT.
    const result = await db.indicator.createMany({
      data: rows,
      skipDuplicates: true,
    });
    report.created = result.count;
    // Anything the unique index rejected was concurrently created, so it is an
    // update from this caller's point of view.
    report.updated += rows.length - result.count;
  }

  if (toTouch.length) {
    // Re-seeing an indicator is meaningful signal: it is still live.
    await db.indicator.updateMany({
      where: { id: { in: toTouch } },
      data: { lastSeen: now, ...(options.sourceId ? { expiresAt } : {}) },
    });
    report.updated += toTouch.length;
  }

  return report;
}
