import Link from "next/link";
import { Play } from "lucide-react";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, NewButton, PageHeader } from "@/components/ui/page";
import { runFeedNow } from "../enrichment/actions";
import { toggleSource } from "./actions";

export const metadata = { title: "Feeds · Pulse Intelligence" };

/**
 * Per-source reliability stats.
 * hitRate  — fraction of the source's indicators that have at least one
 *            enrichment with a malicious score ≥ 50. A high rate means the
 *            feed is sending real threats; a low rate means it's noisy.
 * dedupRate — fraction of ingested items that were duplicates of existing
 *            indicators. High dedup is fine (overlap is expected in quality
 *            feeds); 0% dedup on a new source is suspicious (no overlap with
 *            any other source = possibly fabricated or low-quality data).
 * avgConf  — average confidence across the source's indicators, as set by
 *            the source's configured defaultConfidence and adjusted by
 *            enrichment feedback.
 */
type ReliabilityStats = {
  sourceId: string;
  hitRate: number;      // 0-1
  dedupRate: number;    // 0-1
  indicatorCount: number;
};

async function computeReliabilityStats(
  sourceIds: string[],
): Promise<Map<string, ReliabilityStats>> {
  if (sourceIds.length === 0) return new Map();

  // All non-whitelisted indicators per source.
  const totals = await db.indicator.groupBy({
    by: ["sourceId"],
    where: { sourceId: { in: sourceIds }, whitelisted: false },
    _count: { id: true },
  });

  // Indicators from these sources that have at least one malicious enrichment.
  const hits = await db.indicator.groupBy({
    by: ["sourceId"],
    where: {
      sourceId: { in: sourceIds },
      whitelisted: false,
      enrichments: { some: { score: { gte: 50 } } },
    },
    _count: { id: true },
  });

  const hitMap = new Map(hits.map((h) => [h.sourceId, h._count.id]));

  const statsMap = new Map<string, ReliabilityStats>();

  for (const t of totals) {
    if (!t.sourceId) continue;
    const total = t._count.id;
    const hitCount = hitMap.get(t.sourceId) ?? 0;
    statsMap.set(t.sourceId, {
      sourceId: t.sourceId,
      hitRate: total > 0 ? hitCount / total : 0,
      dedupRate: 0, // filled below from source.itemsDuped
      indicatorCount: total,
    });
  }

  return statsMap;
}

/** A feed that silently stops returning data is worse than no feed at all. */
function healthTone(status: string | null, lastRunAt: Date | null): string {
  if (status === "error") return "text-danger";
  if (!lastRunAt) return "text-ink-faint";
  const ageHours = (Date.now() - lastRunAt.getTime()) / 3_600_000;
  // Most feeds are hourly; a day of silence means something is wrong.
  if (ageHours > 24) return "text-warn";
  return "text-ok";
}

export default async function FeedsPage() {
  const user = await getCurrentUser();
  const canManage = user && hasRole(user, "ADMIN");
  const canRun = user && hasRole(user, "ANALYST");

  const sources = await db.source.findMany({
    orderBy: [{ enabled: "desc" }, { name: "asc" }],
    include: { _count: { select: { indicators: true, newsItems: true } } },
  });

  const reliabilityStats = await computeReliabilityStats(
    sources.map((s) => s.id),
  );

  // Patch dedupRate from source.itemsDuped — already tracked by the ingestor.
  for (const s of sources) {
    const stat = reliabilityStats.get(s.id);
    if (stat && s.itemsIngested > 0) {
      stat.dedupRate = s.itemsDuped / s.itemsIngested;
    }
  }

  const healthy = sources.filter((s) => s.lastStatus === "ok").length;
  const erroring = sources.filter((s) => s.lastStatus === "error").length;
  const neverRun = sources.filter((s) => !s.lastRunAt).length;

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Feeds"
        description="Automated intelligence sources. The worker runs these on their own schedules."
        action={canManage ? <NewButton href="/feeds/new" label="New source" /> : null}
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-4">
        {[
          { label: "Sources", value: sources.length, tone: "text-ink" },
          { label: "Healthy", value: healthy, tone: "text-ok" },
          { label: "Erroring", value: erroring, tone: erroring ? "text-danger" : "text-ink-muted" },
          { label: "Never run", value: neverRun, tone: neverRun ? "text-warn" : "text-ink-muted" },
        ].map((s) => (
          <Card key={s.label} className="p-4">
            <p className="text-xs text-ink-muted">{s.label}</p>
            <p className={`tabular mt-1.5 text-2xl font-semibold ${s.tone}`}>{s.value}</p>
          </Card>
        ))}
      </div>

      <Card>
        {sources.length === 0 ? (
          <EmptyState
            title="No sources configured"
            description="A source records where indicators came from, and sets their default confidence and decay. Create one to attribute your imports."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Type</Th>
                <Th>Schedule</Th>
                <Th className="text-right">Ingested</Th>
                <Th className="text-right" title="Fraction of ingested items that were already known — high overlap is normal for quality feeds">Dedup %</Th>
                <Th title="% of this source's indicators confirmed malicious by enrichment (score ≥ 50)">Hit rate</Th>
                <Th>Last run</Th>
                <Th>Health</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => (
                <Tr key={s.id} data-reliability={reliabilityStats.get(s.id)?.hitRate ?? 0}>
                  <Td>
                    {canManage ? (
                      <Link
                        href={`/feeds/${s.id}/edit`}
                        className="font-medium text-ink hover:text-brand"
                      >
                        {s.name}
                      </Link>
                    ) : (
                      <span className="font-medium text-ink">{s.name}</span>
                    )}
                    {s.url ? (
                      <div className="truncate text-[11px] text-ink-faint">{s.url}</div>
                    ) : null}
                  </Td>
                  <Td className="text-xs text-ink-muted">{s.type}</Td>
                  <Td className="font-mono text-xs text-ink-muted">
                    {s.schedule ?? <Muted>manual</Muted>}
                  </Td>
                  <Td className="tabular text-right text-xs">
                    {s.itemsIngested.toLocaleString()}
                  </Td>
                  {(() => {
                    const stat = reliabilityStats.get(s.id);
                    const dedupPct = stat ? Math.round(stat.dedupRate * 100) : 0;
                    return (
                      <Td className="tabular text-right text-xs text-ink-muted">
                        {s.itemsIngested > 0 ? `${dedupPct}%` : <Muted>—</Muted>}
                      </Td>
                    );
                  })()}
                  {(() => {
                    const stat = reliabilityStats.get(s.id);
                    if (!stat || stat.indicatorCount === 0) {
                      return <Td><Muted className="text-xs">no data</Muted></Td>;
                    }
                    const pct = Math.round(stat.hitRate * 100);
                    const color =
                      pct >= 40 ? "text-ok" :
                      pct >= 20 ? "text-warn" :
                      pct >= 5  ? "text-orange-500" :
                                  "text-ink-faint";
                    return (
                      <Td title={`${stat.indicatorCount} indicators; ${pct}% confirmed malicious by enrichment`}>
                        <div className="flex items-center gap-1.5">
                          <div className="h-1.5 w-10 overflow-hidden rounded-full bg-surface-3">
                            <div
                              className={`h-full rounded-full ${
                                pct >= 40 ? "bg-ok" :
                                pct >= 20 ? "bg-warn" :
                                pct >= 5  ? "bg-orange-500" :
                                            "bg-ink-faint"
                              }`}
                              style={{ width: `${Math.max(2, pct)}%` }}
                            />
                          </div>
                          <span className={`tabular text-xs ${color}`}>{pct}%</span>
                        </div>
                      </Td>
                    );
                  })()}
                  <Td className="tabular text-xs text-ink-muted">
                    {s.lastRunAt
                      ? s.lastRunAt.toISOString().slice(0, 16).replace("T", " ")
                      : <Muted>never</Muted>}
                  </Td>
                  <Td>
                    <span
                      className={`text-xs ${healthTone(s.lastStatus, s.lastRunAt)}`}
                      title={s.lastError ?? undefined}
                    >
                      {s.lastStatus === "error"
                        ? "error"
                        : !s.lastRunAt
                          ? "pending"
                          : "ok"}
                    </span>
                    {s.errorCount > 0 ? (
                      <span className="tabular block text-[10px] text-ink-faint">
                        {s.errorCount} err
                      </span>
                    ) : null}
                  </Td>
                  <Td>
                    {canManage ? (
                      <form action={toggleSource}>
                        <input type="hidden" name="id" value={s.id} />
                        <input
                          type="hidden"
                          name="enabled"
                          value={s.enabled ? "" : "true"}
                        />
                        <button
                          type="submit"
                          className={`rounded px-1.5 py-0.5 text-xs ${
                            s.enabled
                              ? "border border-ok/40 bg-ok/10 text-ok"
                              : "border border-line bg-surface-2 text-ink-faint"
                          }`}
                        >
                          {s.enabled ? "enabled" : "disabled"}
                        </button>
                      </form>
                    ) : (
                      <span className="text-xs text-ink-muted">
                        {s.enabled ? "enabled" : "disabled"}
                      </span>
                    )}
                  </Td>
                  <Td>
                    {canRun ? (
                      <form action={runFeedNow}>
                        <input type="hidden" name="sourceId" value={s.id} />
                        <button
                          type="submit"
                          title={`Run ${s.name} now`}
                          className="grid size-6 place-items-center rounded text-ink-faint hover:bg-surface-2 hover:text-brand"
                        >
                          <Play className="size-3.5" />
                        </button>
                      </form>
                    ) : null}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}
