import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";
import { Table, Td, Th, Tr, Pagination } from "@/components/ui/table";
import { Muted, PageHeader, Tag } from "@/components/ui/page";

export const metadata = { title: "Audit log - Pulse Intelligence" };

const PAGE_SIZE = 50;

function summarizeChanges(changes: unknown): string {
  if (!changes) return "";
  const text = JSON.stringify(changes);
  if (!text) return "";
  return text.length > 180 ? `${text.slice(0, 180)}...` : text;
}

export default async function AuditPage(props: {
  searchParams: Promise<{ page?: string }>;
}) {
  await requireRole("ADMIN");

  const params = await props.searchParams;
  const page = Math.max(1, Number(params.page) || 1);

  const [rows, total] = await Promise.all([
    db.auditLog.findMany({
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: { user: { select: { name: true, email: true } } },
    }),
    db.auditLog.count(),
  ]);

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        title="Audit log"
        description="Administrative trail of authentication events, analyst actions, imports, exports, and enrichment activity."
      />

      <Card>
        <CardHeader
          title="Recent events"
          hint="Newest first. Payloads are truncated in the table; inspect the database for full forensic detail."
        />
        {rows.length === 0 ? (
          <EmptyState
            title="No audit events"
            description="Events appear here after sign-in, edits, imports, exports, and other tracked actions."
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Time</Th>
                  <Th>Action</Th>
                  <Th>Entity</Th>
                  <Th>User</Th>
                  <Th>Changes</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <Tr key={row.id}>
                    <Td className="tabular text-xs text-ink-muted">
                      {row.createdAt.toISOString().slice(0, 16).replace("T", " ")}
                    </Td>
                    <Td>
                      <Tag>{row.action}</Tag>
                    </Td>
                    <Td>
                      <div className="text-sm text-ink">{row.entityType}</div>
                      {row.entityId ? (
                        <div className="font-mono text-[11px] text-ink-faint">{row.entityId}</div>
                      ) : null}
                    </Td>
                    <Td className="text-xs text-ink-muted">
                      {row.user ? (
                        <>
                          <span className="block text-ink">{row.user.name}</span>
                          <span>{row.user.email}</span>
                        </>
                      ) : (
                        <Muted>system</Muted>
                      )}
                    </Td>
                    <Td className="max-w-[420px]">
                      {row.changes ? (
                        <code className="block truncate font-mono text-[11px] text-ink-muted">
                          {summarizeChanges(row.changes)}
                        </code>
                      ) : (
                        <Muted>-</Muted>
                      )}
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
              basePath="/audit"
            />
          </>
        )}
      </Card>
    </div>
  );
}
