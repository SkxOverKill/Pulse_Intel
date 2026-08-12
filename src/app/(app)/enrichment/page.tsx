import { Activity, AlertTriangle, ListChecks, Search } from "lucide-react";
import { db } from "@/lib/db";
import { hasRole, requireUser } from "@/lib/auth/dal";
import { configuredProviders } from "@/lib/enrichment/registry";
import { estimateDrainMs, getQuotaStatus } from "@/lib/enrichment/limiter";
import { getQueueStats } from "@/lib/queue/queues";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";
import { PageHeader, SecondaryLink } from "@/components/ui/page";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { EnrichAllButton } from "./enrich-button";

export const metadata = { title: "Enrichment · Pulse Intelligence" };

/** Human-readable duration. Bulk enrichment ETAs are measured in days. */
function humanizeMs(ms: number): string {
  if (ms <= 0) return "immediately";
  const min = Math.ceil(ms / 60_000);
  if (min < 60) return `~${min} min`;
  const hours = Math.round(min / 60);
  if (hours < 48) return `~${hours} h`;
  return `~${Math.round(hours / 24)} days`;
}

export default async function EnrichmentPage() {
  const user = await requireUser();
  const isAdmin = hasRole(user, "ADMIN");

  const providers = configuredProviders();

  // Batched into a single raw query to avoid multiple round-trips and
  // concurrent query pressure on the local dev Postgres (see src/lib/db.ts).
  const counts = await db.$queryRaw<
    [{ pending: bigint; enriched: bigint; malicious: bigint; failed: bigint }]
  >`
    SELECT 
      (SELECT count(*)::bigint FROM "Indicator" WHERE "whitelisted" = false AND NOT EXISTS (SELECT 1 FROM "Enrichment" WHERE "indicatorId" = "Indicator"."id")) AS pending,
      (SELECT count(*)::bigint FROM "Indicator" WHERE EXISTS (SELECT 1 FROM "Enrichment" WHERE "indicatorId" = "Indicator"."id")) AS enriched,
      (SELECT count(*)::bigint FROM "Enrichment" WHERE "verdict" = 'MALICIOUS') AS malicious,
      (SELECT count(*)::bigint FROM "Enrichment" WHERE "error" IS NOT NULL) AS failed
  `;
  const pending = Number(counts[0].pending);
  const enriched = Number(counts[0].enriched);
  const malicious = Number(counts[0].malicious);
  const failed = Number(counts[0].failed);

  const quotas = await Promise.all(
    providers.map(async (p) => {
      const status = await getQuotaStatus(p.name, p.quota);
      return {
        provider: p,
        status,
        etaMs: estimateDrainMs(pending, p.quota, status),
      };
    }),
  );

  let queue: Awaited<ReturnType<typeof getQueueStats>> | null = null;
  let queueError: string | null = null;
  try {
    queue = await getQueueStats();
  } catch (err) {
    queueError = err instanceof Error ? err.message : String(err);
  }

  // The scarcest provider governs how long a full pass actually takes — but
  // VirusTotal is excluded from the automatic bulk-enrichment path (see
  // enrichAll() in lib/enrichment/enrich.ts), so its quota shouldn't inflate
  // the ETA for a queue it never touches.
  const worstEta = quotas.reduce(
    (max, q) => (q.provider.name === "virustotal" ? max : Math.max(max, q.etaMs)),
    0,
  );

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        title="Enrichment"
        description="Provider lookups are cache-first and rate-limited. Free-tier quotas are the binding constraint on bulk work."
        action={
          <div className="flex shrink-0 items-center gap-2">
            <SecondaryLink href="/enrichment/lookup">
              <Search className="size-4" />
              Lookup
            </SecondaryLink>
            <SecondaryLink href="/enrichment/bulk">
              <ListChecks className="size-4" />
              Bulk lookup
            </SecondaryLink>
            {isAdmin ? <EnrichAllButton pending={pending} /> : null}
          </div>
        }
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: "Awaiting enrichment", value: pending },
          { label: "Enriched", value: enriched },
          { label: "Malicious verdicts", value: malicious },
          { label: "Provider errors", value: failed },
        ].map((s) => (
          <Card key={s.label} className="p-4">
            <p className="text-xs text-ink-muted">{s.label}</p>
            <p className="tabular mt-1.5 text-2xl font-semibold text-ink">
              {s.value.toLocaleString()}
            </p>
          </Card>
        ))}
      </div>

      {pending > 0 && worstEta > 3 * 86_400_000 ? (
        <div className="mb-4 flex items-start gap-2 rounded-[--radius-card] border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-warn">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <div>
            <p className="font-medium">
              A full pass would take {humanizeMs(worstEta)} at current free-tier quotas.
            </p>
            <p className="mt-0.5 text-xs opacity-90">
              This is a hard limit of the provider plans, not a queue backlog.
              Enriching selectively — or upgrading the VirusTotal plan — are the
              only ways to make this materially faster.
            </p>
          </div>
        </div>
      ) : null}

      <Card className="mb-4">
        <CardHeader
          title="Provider quotas"
          hint="Live counters from the Redis rate limiter"
        />
        {quotas.length === 0 ? (
          <EmptyState
            title="No providers configured"
            description="Set VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY or OTX_API_KEY in .env."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Provider</Th>
                <Th className="text-right">This minute</Th>
                <Th className="text-right">Today</Th>
                <Th>Daily quota</Th>
                <Th className="text-right">ETA for {pending.toLocaleString()} pending</Th>
              </tr>
            </thead>
            <tbody>
              {quotas.map(({ provider, status, etaMs }) => {
                const dayPct =
                  status.dayMax != null
                    ? Math.min(100, Math.round((status.dayUsed / status.dayMax) * 100))
                    : 0;
                return (
                  <Tr key={provider.name}>
                    <Td>
                      <span className="text-sm text-ink">{provider.label}</span>
                      <span className="block text-[11px] text-ink-faint">
                        cache {Math.round(provider.ttlMs / 3_600_000)}h
                      </span>
                    </Td>
                    <Td className="tabular text-right text-xs text-ink-muted">
                      {status.minuteMax != null
                        ? `${status.minuteUsed} / ${status.minuteMax}`
                        : "—"}
                    </Td>
                    <Td className="tabular text-right text-xs text-ink-muted">
                      {status.dayMax != null
                        ? `${status.dayUsed} / ${status.dayMax}`
                        : `${status.dayUsed}`}
                    </Td>
                    <Td>
                      {status.dayMax != null ? (
                        <span className="inline-flex items-center gap-2">
                          <span className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-3">
                            <span
                              className={`block h-full rounded-full ${
                                dayPct >= 90
                                  ? "bg-danger"
                                  : dayPct >= 60
                                    ? "bg-warn"
                                    : "bg-ok"
                              }`}
                              style={{ width: `${dayPct}%` }}
                            />
                          </span>
                          <span className="tabular text-[11px] text-ink-faint">
                            {dayPct}%
                          </span>
                        </span>
                      ) : (
                        <span className="text-xs text-ink-faint">unmetered</span>
                      )}
                    </Td>
                    <Td className="tabular text-right text-xs text-ink-muted">
                      {provider.name === "virustotal" ? (
                        <span className="text-ink-faint">not used for bulk</span>
                      ) : pending === 0 ? (
                        "—"
                      ) : (
                        humanizeMs(etaMs)
                      )}
                    </Td>
                  </Tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader title="Queue" hint="BullMQ job counts" />
        {queueError ? (
          <div className="px-4 py-4 text-sm text-danger">
            Could not reach Redis: {queueError}
          </div>
        ) : queue ? (
          <div className="grid grid-cols-2 gap-px bg-line sm:grid-cols-5">
            {Object.entries(queue.enrichment).map(([state, count]) => (
              <div key={state} className="bg-surface px-4 py-3">
                <p className="text-[11px] uppercase tracking-wide text-ink-faint">
                  {state}
                </p>
                <p className="tabular mt-0.5 text-lg font-semibold text-ink">
                  {count}
                </p>
              </div>
            ))}
          </div>
        ) : null}
        <p className="flex items-center gap-1.5 border-t border-line px-4 py-2.5 text-xs text-ink-faint">
          <Activity className="size-3.5" />
          Jobs are processed by the worker — run `npm run worker` alongside the app.
        </p>
      </Card>
    </div>
  );
}
