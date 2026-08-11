import Link from "next/link";
import { Bell, Crosshair } from "lucide-react";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, NewButton, PageHeader } from "@/components/ui/page";
import { validateHuntQuery, describeHunt } from "@/lib/hunting/schema";
import { acknowledgeAlert } from "./actions";

export const metadata = { title: "Threat Hunting · Pulse Intelligence" };

function summarize(query: unknown): string {
  const v = validateHuntQuery(query);
  return v.ok ? describeHunt(v.ast) : "invalid query";
}

export default async function HuntingPage() {
  const user = await getCurrentUser();
  const canManage = user && hasRole(user, "ANALYST");

  const [hunts, alerts] = await Promise.all([
    db.huntQuery.findMany({
      orderBy: [{ updatedAt: "desc" }],
      include: {
        owner: { select: { name: true } },
        _count: { select: { alerts: { where: { acknowledged: false } } } },
      },
    }),
    db.huntAlert.findMany({
      where: { acknowledged: false },
      orderBy: { createdAt: "desc" },
      take: 20,
      include: { hunt: { select: { id: true, name: true } } },
    }),
  ]);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Threat Hunting"
        description="Structured queries over the indicator set. Schedule one and it alerts you when something new matches."
        action={canManage ? <NewButton href="/hunting/new" label="New hunt" /> : null}
      />

      {alerts.length > 0 ? (
        <Card className="mb-4 border-warn/40">
          <div className="flex items-center gap-2 border-b border-line px-4 py-3">
            <Bell className="size-4 text-warn" />
            <h2 className="text-sm font-semibold text-ink">
              {alerts.length} open alert{alerts.length === 1 ? "" : "s"}
            </h2>
          </div>
          <ul className="divide-y divide-line/60">
            {alerts.map((a) => (
              <li key={a.id} className="flex items-center gap-3 px-4 py-2.5">
                <div className="min-w-0 flex-1">
                  <Link
                    href={`/hunting/${a.hunt.id}`}
                    className="text-sm font-medium text-ink hover:text-brand"
                  >
                    {a.hunt.name}
                  </Link>
                  <span className="ml-2 text-xs text-ink-muted">
                    {a.newCount} new match{a.newCount === 1 ? "" : "es"} ·{" "}
                    {a.matchCount} total
                  </span>
                </div>
                <span className="tabular text-xs text-ink-faint">
                  {a.createdAt.toISOString().slice(0, 16).replace("T", " ")}
                </span>
                {canManage ? (
                  <form action={acknowledgeAlert}>
                    <input type="hidden" name="id" value={a.id} />
                    <button
                      type="submit"
                      className="rounded border border-line bg-surface px-2 py-1 text-xs text-ink-muted hover:bg-surface-2 hover:text-ink"
                    >
                      Acknowledge
                    </button>
                  </form>
                ) : null}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <Card>
        {hunts.length === 0 ? (
          <EmptyState
            title="No hunts yet"
            description="A hunt is a saved query over your indicators. Give it a schedule and turn on alerting to be told when new IOCs match — a fresh C2 IP, a new high-severity hash from a feed."
            action={
              canManage ? (
                <NewButton href="/hunting/new" label="Create your first hunt" />
              ) : null
            }
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Query</Th>
                <Th>Schedule</Th>
                <Th className="text-right">Last hits</Th>
                <Th>Last run</Th>
                <Th>Alerting</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {hunts.map((h) => (
                <Tr key={h.id} href={`/hunting/${h.id}`}>
                  <Td>
                    <Link
                      href={`/hunting/${h.id}`}
                      className="flex items-center gap-2 font-medium text-ink hover:text-brand"
                    >
                      <Crosshair className="size-3.5 shrink-0 text-ink-faint" />
                      {h.name}
                    </Link>
                    {h._count.alerts > 0 ? (
                      <span className="ml-5 mt-0.5 inline-block rounded bg-warn/15 px-1.5 py-px text-[10px] font-medium text-warn">
                        {h._count.alerts} open alert{h._count.alerts === 1 ? "" : "s"}
                      </span>
                    ) : null}
                  </Td>
                  <Td className="max-w-md">
                    <span className="block truncate text-xs text-ink-muted" title={summarize(h.query)}>
                      {summarize(h.query)}
                    </span>
                  </Td>
                  <Td className="font-mono text-xs text-ink-muted">
                    {h.schedule ?? <Muted>on demand</Muted>}
                  </Td>
                  <Td className="tabular text-right text-xs">
                    {h.lastRunAt ? h.lastHitCount.toLocaleString() : <Muted>—</Muted>}
                  </Td>
                  <Td className="tabular text-xs text-ink-muted">
                    {h.lastRunAt
                      ? h.lastRunAt.toISOString().slice(0, 16).replace("T", " ")
                      : <Muted>never</Muted>}
                  </Td>
                  <Td>
                    {h.notifyOnHit ? (
                      <span className="inline-flex items-center gap-1 text-xs text-ok">
                        <Bell className="size-3" /> on
                      </span>
                    ) : (
                      <Muted>off</Muted>
                    )}
                  </Td>
                  <Td className="text-xs text-ink-faint">
                    {h.owner?.name ?? <Muted>—</Muted>}
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
