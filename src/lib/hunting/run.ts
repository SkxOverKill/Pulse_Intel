/**
 * Hunt execution. Shared by the server (a "Run now" click) and the worker (a
 * scheduled run), so it carries no `server-only` marker and never touches
 * request-scoped APIs like `next/headers` — the worker has neither.
 *
 * The interesting part is "new since last run". A hunt that re-alerts on the
 * same 400 indicators every hour is noise an analyst learns to ignore, which is
 * the same as having no alert. So a scheduled run compares against `lastRunAt`
 * and only alerts on indicators created since — the genuinely new matches.
 */
import { db } from "@/lib/db";
import {
  describeHunt,
  validateHuntQuery,
  type HuntQueryAst,
} from "@/lib/hunting/schema";
import { compileWhere } from "@/lib/hunting/compile";

export type HuntPreview = {
  total: number;
  sample: {
    id: string;
    type: string;
    value: string;
    severity: string;
    confidence: number;
    lastSeen: Date;
    sourceName: string | null;
  }[];
};

const SAMPLE_SIZE = 50;

/**
 * Runs a validated AST read-only and returns the current match count plus a
 * sample. Used by the detail page to show "what would this hunt match right
 * now" without persisting anything.
 */
export async function previewHunt(ast: HuntQueryAst): Promise<HuntPreview> {
  const where = compileWhere(ast);
  const [total, rows] = await Promise.all([
    db.indicator.count({ where }),
    db.indicator.findMany({
      where,
      orderBy: { lastSeen: "desc" },
      take: SAMPLE_SIZE,
      select: {
        id: true,
        type: true,
        value: true,
        severity: true,
        confidence: true,
        lastSeen: true,
        source: { select: { name: true } },
      },
    }),
  ]);

  return {
    total,
    sample: rows.map((r) => ({
      id: r.id,
      type: r.type,
      value: r.value,
      severity: r.severity,
      confidence: r.confidence,
      lastSeen: r.lastSeen,
      sourceName: r.source?.name ?? null,
    })),
  };
}

export type HuntRunResult =
  | { ok: true; matchCount: number; newCount: number; alerted: boolean }
  | { ok: false; error: string };

/**
 * Executes a saved hunt and records the run.
 *
 * `previousRunAt` is read before the write so "new" is measured against the last
 * time this hunt actually ran, not against now. A first run (no prior timestamp)
 * treats every match as new — the analyst is seeing this hunt's results for the
 * first time, so that is the honest baseline.
 *
 * Writes an alert only when the hunt opted in (`notifyOnHit`) and there is
 * something new to say. A run that finds nothing new updates `lastRunAt` and
 * moves on silently.
 */
export async function runHunt(huntId: string): Promise<HuntRunResult> {
  const hunt = await db.huntQuery.findUnique({ where: { id: huntId } });
  if (!hunt) return { ok: false, error: "Hunt not found." };

  const validated = validateHuntQuery(hunt.query);
  if (!validated.ok) {
    return { ok: false, error: `Invalid query: ${validated.errors.join("; ")}` };
  }

  const where = compileWhere(validated.ast);
  const previousRunAt = hunt.lastRunAt;

  const matchCount = await db.indicator.count({ where });

  // New matches: rows that match now and were created since the last run. On a
  // first run everything counts, capped so a huge first hunt doesn't try to
  // stuff every id into one alert row.
  const newWhere = previousRunAt
    ? { AND: [where, { createdAt: { gt: previousRunAt } }] }
    : where;

  const newRows = await db.indicator.findMany({
    where: newWhere,
    orderBy: { createdAt: "desc" },
    take: 500,
    select: { id: true },
  });
  const newCount = previousRunAt
    ? newRows.length
    : await db.indicator.count({ where: newWhere });

  await db.huntQuery.update({
    where: { id: huntId },
    data: { lastRunAt: new Date(), lastHitCount: matchCount },
  });

  let alerted = false;
  if (hunt.notifyOnHit && newRows.length > 0) {
    await db.huntAlert.create({
      data: {
        huntId,
        matchCount,
        newCount,
        indicatorIds: newRows.map((r) => r.id),
      },
    });
    alerted = true;
  }

  return { ok: true, matchCount, newCount, alerted };
}

/** Convenience for logs and audit entries. */
export function huntSummary(query: unknown): string {
  const v = validateHuntQuery(query);
  return v.ok ? describeHunt(v.ast) : "invalid query";
}
