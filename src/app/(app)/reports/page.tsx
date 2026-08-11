import Link from "next/link";
import { Clock3 } from "lucide-react";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import { Card, ConfidenceBar, EmptyState, TlpBadge } from "@/components/ui/primitives";
import { Pagination, Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, NewButton, PageHeader, SecondaryLink, Tag } from "@/components/ui/page";

export const metadata = { title: "Reports · Pulse Intelligence" };

const PAGE_SIZE = 25;

export default async function ReportsPage(props: {
  searchParams: Promise<{ page?: string }>;
}) {
  const params = await props.searchParams;
  const user = await getCurrentUser();
  const page = Math.max(1, Number(params.page) || 1);

  const [reports, total] = await Promise.all([
    db.report.findMany({
      orderBy: [{ published: "desc" }, { updatedAt: "desc" }],
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: {
        author: { select: { name: true } },
        _count: { select: { indicators: true, actors: true } },
      },
    }),
    db.report.count(),
  ]);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Reports"
        description="Analyst-authored intelligence. IOCs can be extracted from the body automatically."
        action={
          <div className="flex shrink-0 items-center gap-2">
            {user && hasRole(user, "ANALYST") ? (
              <SecondaryLink href="/reports/scheduled">
                <Clock3 className="size-4" />
                Scheduled reports
              </SecondaryLink>
            ) : null}
            {user && hasRole(user, "ANALYST") ? (
              <NewButton href="/reports/new" label="New report" />
            ) : null}
          </div>
        }
      />

      <Card>
        {reports.length === 0 ? (
          <EmptyState
            title="No reports yet"
            description="Write up an intrusion, a campaign, or a piece of malware. Paste IOCs into the body and extract them in one click."
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Title</Th>
                  <Th>Status</Th>
                  <Th>Author</Th>
                  <Th>Tags</Th>
                  <Th className="text-right">Links</Th>
                  <Th>Confidence</Th>
                  <Th>TLP</Th>
                  <Th>Updated</Th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <Tr key={r.id} href={`/reports/${r.id}`}>
                    <Td className="max-w-sm">
                      <Link
                        href={`/reports/${r.id}`}
                        className="block truncate font-medium text-ink hover:text-brand"
                      >
                        {r.title}
                      </Link>
                    </Td>
                    <Td>
                      {r.published ? (
                        <span className="text-xs text-ok">published</span>
                      ) : (
                        <span className="text-xs text-ink-faint">draft</span>
                      )}
                    </Td>
                    <Td className="text-xs text-ink-muted">
                      {r.author?.name ?? <Muted>—</Muted>}
                    </Td>
                    <Td>
                      {r.tags.length ? (
                        <div className="flex flex-wrap gap-1">
                          {r.tags.slice(0, 2).map((t) => (
                            <Tag key={t}>{t}</Tag>
                          ))}
                        </div>
                      ) : (
                        <Muted>—</Muted>
                      )}
                    </Td>
                    <Td className="tabular text-right text-xs text-ink-muted">
                      {r._count.indicators}I · {r._count.actors}A
                    </Td>
                    <Td>
                      <ConfidenceBar value={r.confidence} />
                    </Td>
                    <Td>
                      <TlpBadge tlp={r.tlp} />
                    </Td>
                    <Td className="tabular text-xs text-ink-muted">
                      {r.updatedAt.toISOString().slice(0, 10)}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              total={total}
              searchParams={params}
              basePath="/reports"
            />
          </>
        )}
      </Card>
    </div>
  );
}
