import Link from "next/link";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, NewButton, PageHeader } from "@/components/ui/page";
import { toggleSource } from "./actions";

export const metadata = { title: "Feeds · Pulse Intelligence" };

export default async function FeedsPage() {
  const user = await getCurrentUser();
  const canManage = user && hasRole(user, "ADMIN");

  const sources = await db.source.findMany({
    orderBy: [{ enabled: "desc" }, { name: "asc" }],
    include: { _count: { select: { indicators: true } } },
  });

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Feeds"
        description="Intelligence sources. Automated polling arrives in Phase 5 — until then these classify manually imported indicators."
        action={canManage ? <NewButton href="/feeds/new" label="New source" /> : null}
      />

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
                <Th className="text-right">Indicators</Th>
                <Th>Default confidence</Th>
                <Th>Decay</Th>
                <Th>Last run</Th>
                <Th>Status</Th>
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
                  <Td className="tabular text-right text-xs">{s._count.indicators}</Td>
                  <Td className="tabular text-xs text-ink-muted">
                    {s.defaultConfidence}%
                  </Td>
                  <Td className="tabular text-xs text-ink-muted">
                    {s.decayHalfLifeDays ? `${s.decayHalfLifeDays}d` : <Muted>never</Muted>}
                  </Td>
                  <Td className="tabular text-xs text-ink-muted">
                    {s.lastRunAt ? s.lastRunAt.toISOString().slice(0, 10) : <Muted>—</Muted>}
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
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}
