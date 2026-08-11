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
                <Th className="text-right">Deduped</Th>
                <Th>Last run</Th>
                <Th>Health</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => (
                <Tr key={s.id}>
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
                  <Td className="tabular text-right text-xs text-ink-faint">
                    {s.itemsDuped.toLocaleString()}
                  </Td>
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
