import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink, Pencil, ScanSearch, Trash2 } from "lucide-react";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import {
  Card,
  CardHeader,
  ConfidenceBar,
  EmptyState,
  TlpBadge,
} from "@/components/ui/primitives";
import { DetailRow, Muted, PageHeader, SecondaryLink, Tag } from "@/components/ui/page";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { deleteReport, extractIndicators } from "../actions";

export async function generateMetadata(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const r = await db.report.findUnique({ where: { id }, select: { title: true } });
  return { title: `${r?.title ?? "Report"} · Pulse Intelligence` };
}

export default async function ReportDetailPage(props: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await props.params;
  const user = await getCurrentUser();

  const report = await db.report.findUnique({
    where: { id },
    include: {
      author: { select: { name: true } },
      indicators: { include: { indicator: true }, take: 100 },
      actors: { include: { actor: true } },
      techniques: { include: { technique: true } },
    },
  });

  if (!report) notFound();

  const canEdit = user && hasRole(user, "ANALYST");
  const canDelete = user && hasRole(user, "ADMIN");

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title={report.title}
        description={report.summary ?? undefined}
        action={
          <div className="flex shrink-0 items-center gap-2">
            {canEdit ? (
              <>
                <form action={extractIndicators}>
                  <input type="hidden" name="reportId" value={report.id} />
                  <button
                    type="submit"
                    title="Find every IOC in the body, ingest it, and link it to this report"
                    className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
                  >
                    <ScanSearch className="size-4" />
                    Extract IOCs
                  </button>
                </form>
                <SecondaryLink href={`/reports/${report.id}/edit`}>
                  <Pencil className="size-4" />
                  Edit
                </SecondaryLink>
              </>
            ) : null}
            {canDelete ? (
              <form action={deleteReport}>
                <input type="hidden" name="id" value={report.id} />
                <button
                  type="submit"
                  className="inline-flex items-center gap-1.5 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger transition-colors hover:bg-danger/20"
                >
                  <Trash2 className="size-4" />
                  Delete
                </button>
              </form>
            ) : null}
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Report" />
            {/* Rendered as preformatted text, not HTML. Reports routinely contain
                live malicious URLs and attacker-controlled strings; running them
                through a markdown-to-HTML renderer would be an XSS sink. A
                sanitising renderer can come later if it earns its keep. */}
            <pre className="overflow-x-auto whitespace-pre-wrap px-4 py-4 font-mono text-xs leading-relaxed text-ink">
              {report.body}
            </pre>
          </Card>

          <Card>
            <CardHeader
              title="Extracted indicators"
              hint={`${report.indicators.length} linked`}
            />
            {report.indicators.length === 0 ? (
              <EmptyState
                title="No indicators linked"
                description="Use Extract IOCs to pull every indicator out of the body and link it here."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Type</Th>
                    <Th>Value</Th>
                    <Th>Confidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {report.indicators.map((i) => (
                    <Tr key={i.indicatorId}>
                      <Td className="text-xs text-ink-muted">{i.indicator.type}</Td>
                      <Td>
                        <Link
                          href={`/indicators/${i.indicatorId}`}
                          className="font-mono text-xs text-ink hover:text-brand"
                        >
                          {i.indicator.value}
                        </Link>
                      </Td>
                      <Td>
                        <ConfidenceBar value={i.confidence} />
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>

        <div className="space-y-4 lg:col-span-1">
          <Card>
            <CardHeader title="Metadata" />
            <dl>
              <DetailRow label="Status">
                {report.published ? (
                  <span className="text-ok">Published</span>
                ) : (
                  <Muted>Draft</Muted>
                )}
              </DetailRow>
              <DetailRow label="Author">
                {report.author?.name ?? <Muted>Unknown</Muted>}
              </DetailRow>
              <DetailRow label="Created">
                {report.createdAt.toISOString().slice(0, 10)}
              </DetailRow>
              <DetailRow label="Updated">
                {report.updatedAt.toISOString().slice(0, 10)}
              </DetailRow>
              <DetailRow label="Confidence">
                <ConfidenceBar value={report.confidence} />
              </DetailRow>
              <DetailRow label="TLP">
                <TlpBadge tlp={report.tlp} />
              </DetailRow>
              <DetailRow label="Source">
                {report.sourceUrl ? (
                  <a
                    href={report.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer nofollow"
                    className="inline-flex items-center gap-1 break-all text-xs text-brand hover:underline"
                  >
                    {report.sourceUrl}
                    <ExternalLink className="size-3 shrink-0" />
                  </a>
                ) : (
                  <Muted>None</Muted>
                )}
              </DetailRow>
              <DetailRow label="Tags">
                {report.tags.length ? (
                  <div className="flex flex-wrap gap-1">
                    {report.tags.map((t) => (
                      <Tag key={t}>{t}</Tag>
                    ))}
                  </div>
                ) : (
                  <Muted>None</Muted>
                )}
              </DetailRow>
            </dl>
          </Card>

          <Card>
            <CardHeader title="Linked actors" />
            {report.actors.length === 0 ? (
              <p className="px-4 py-4 text-sm text-ink-faint">None linked.</p>
            ) : (
              <ul className="divide-y divide-line/60">
                {report.actors.map((a) => (
                  <li key={a.actorId} className="flex items-center justify-between gap-2 px-4 py-2.5">
                    <Link
                      href={`/actors/${a.actorId}`}
                      className="text-sm text-ink hover:text-brand"
                    >
                      {a.actor.name}
                    </Link>
                    <ConfidenceBar value={a.confidence} />
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
