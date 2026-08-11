import Link from "next/link";
import { Play } from "lucide-react";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, NewButton, PageHeader } from "@/components/ui/page";
import { deleteScheduledReport, runScheduledReportNow, toggleScheduledReport } from "./actions";

export const metadata = { title: "Scheduled reports · Pulse Intelligence" };

export default async function ScheduledReportsPage() {
  const user = await getCurrentUser();
  const canManage = user && hasRole(user, "ANALYST");

  const reports = await db.scheduledReport.findMany({
    orderBy: [{ enabled: "desc" }, { name: "asc" }],
    include: { owner: { select: { name: true } } },
  });

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-1 flex items-center gap-2 text-xs text-ink-faint">
        <Link href="/reports" className="hover:text-ink-muted">
          Reports
        </Link>
        <span>/</span>
      </div>
      <PageHeader
        title="Scheduled reports"
        description="Recurring intelligence summaries. Each run files a normal report, generated from the platform's own data."
        action={canManage ? <NewButton href="/reports/scheduled/new" label="New schedule" /> : null}
      />

      <Card>
        {reports.length === 0 ? (
          <EmptyState
            title="No scheduled reports"
            description="Create one to get a recurring weekly (or any cadence) summary of new indicators, KEV additions, hunt alerts, and feed health — filed automatically to Reports."
            action={
              canManage ? (
                <NewButton href="/reports/scheduled/new" label="Create your first schedule" />
              ) : null
            }
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Schedule</Th>
                <Th>Last run</Th>
                <Th>Status</Th>
                <Th>Owner</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <Tr key={r.id}>
                  <Td>
                    {canManage ? (
                      <Link
                        href={`/reports/scheduled/${r.id}/edit`}
                        className="font-medium text-ink hover:text-brand"
                      >
                        {r.name}
                      </Link>
                    ) : (
                      <span className="font-medium text-ink">{r.name}</span>
                    )}
                    {r.description ? (
                      <div className="truncate text-[11px] text-ink-faint">{r.description}</div>
                    ) : null}
                  </Td>
                  <Td className="font-mono text-xs text-ink-muted">{r.schedule}</Td>
                  <Td className="tabular text-xs text-ink-muted">
                    {r.lastRunAt
                      ? r.lastRunAt.toISOString().slice(0, 16).replace("T", " ")
                      : <Muted>never</Muted>}
                  </Td>
                  <Td>
                    {canManage ? (
                      <form action={toggleScheduledReport}>
                        <input type="hidden" name="id" value={r.id} />
                        <input type="hidden" name="enabled" value={r.enabled ? "" : "true"} />
                        <button
                          type="submit"
                          className={`rounded px-1.5 py-0.5 text-xs ${
                            r.enabled
                              ? "border border-ok/40 bg-ok/10 text-ok"
                              : "border border-line bg-surface-2 text-ink-faint"
                          }`}
                        >
                          {r.enabled ? "enabled" : "disabled"}
                        </button>
                      </form>
                    ) : (
                      <span className="text-xs text-ink-muted">
                        {r.enabled ? "enabled" : "disabled"}
                      </span>
                    )}
                  </Td>
                  <Td className="text-xs text-ink-faint">{r.owner?.name ?? <Muted>—</Muted>}</Td>
                  <Td>
                    <div className="flex items-center justify-end gap-1">
                      {canManage ? (
                        <form action={runScheduledReportNow}>
                          <input type="hidden" name="id" value={r.id} />
                          <button
                            type="submit"
                            title={`Run ${r.name} now`}
                            className="grid size-6 place-items-center rounded text-ink-faint hover:bg-surface-2 hover:text-brand"
                          >
                            <Play className="size-3.5" />
                          </button>
                        </form>
                      ) : null}
                      {canManage ? (
                        <form action={deleteScheduledReport}>
                          <input type="hidden" name="id" value={r.id} />
                          <button
                            type="submit"
                            className="rounded border border-line px-2 py-1 text-xs text-ink-muted hover:border-danger/40 hover:bg-danger/10 hover:text-danger"
                          >
                            Delete
                          </button>
                        </form>
                      ) : null}
                    </div>
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
