import Link from "next/link";
import { notFound } from "next/navigation";
import { AlertTriangle, Bell, Pencil, Play } from "lucide-react";
import type { Severity } from "@/generated/prisma/enums";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import {
  Card,
  CardHeader,
  ConfidenceBar,
  EmptyState,
  SeverityBadge,
} from "@/components/ui/primitives";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { DetailRow, Muted, SecondaryLink } from "@/components/ui/page";
import { validateHuntQuery, describeHunt } from "@/lib/hunting/schema";
import { previewHunt } from "@/lib/hunting/run";
import { deleteHunt, runHuntNow } from "../actions";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const hunt = await db.huntQuery.findUnique({ where: { id }, select: { name: true } });
  return { title: `${hunt?.name ?? "Hunt"} · Pulse Intelligence` };
}

export default async function HuntDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const user = await getCurrentUser();
  const canManage = user && hasRole(user, "ANALYST");

  const hunt = await db.huntQuery.findUnique({
    where: { id },
    include: {
      owner: { select: { name: true } },
      alerts: { orderBy: { createdAt: "desc" }, take: 10 },
    },
  });
  if (!hunt) notFound();

  const validated = validateHuntQuery(hunt.query);
  const preview = validated.ok ? await previewHunt(validated.ast) : null;

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="mb-1 flex items-center gap-2 text-xs text-ink-faint">
            <Link href="/hunting" className="hover:text-ink-muted">
              Threat Hunting
            </Link>
            <span>/</span>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-ink">{hunt.name}</h1>
          {hunt.description ? (
            <p className="mt-1 text-sm text-ink-muted">{hunt.description}</p>
          ) : null}
        </div>
        {canManage ? (
          <div className="flex shrink-0 items-center gap-2">
            <form action={runHuntNow}>
              <input type="hidden" name="id" value={hunt.id} />
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-md bg-brand px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover"
              >
                <Play className="size-4" />
                Run now
              </button>
            </form>
            <SecondaryLink href={`/hunting/${hunt.id}/edit`}>
              <Pencil className="size-4" />
              Edit
            </SecondaryLink>
            <form action={deleteHunt}>
              <input type="hidden" name="id" value={hunt.id} />
              <button
                type="submit"
                className="rounded-md border border-line px-3 py-2 text-sm text-ink-muted transition-colors hover:border-danger/40 hover:bg-danger/10 hover:text-danger"
              >
                Delete
              </button>
            </form>
          </div>
        ) : null}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-1">
          <Card>
            <CardHeader title="Definition" />
            <dl>
              <DetailRow label="Query">
                {validated.ok ? (
                  <span className="text-ink">{describeHunt(validated.ast)}</span>
                ) : (
                  <span className="flex items-center gap-1.5 text-danger">
                    <AlertTriangle className="size-3.5" /> invalid query
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Schedule">
                {hunt.schedule ? (
                  <code className="font-mono text-xs text-ink">{hunt.schedule}</code>
                ) : (
                  <Muted>on demand only</Muted>
                )}
              </DetailRow>
              <DetailRow label="Alerting">
                {hunt.notifyOnHit ? (
                  <span className="inline-flex items-center gap-1 text-ok">
                    <Bell className="size-3.5" /> on new matches
                  </span>
                ) : (
                  <Muted>off</Muted>
                )}
              </DetailRow>
              <DetailRow label="Last run">
                {hunt.lastRunAt ? (
                  <span className="tabular">
                    {hunt.lastRunAt.toISOString().slice(0, 16).replace("T", " ")} ·{" "}
                    {hunt.lastHitCount.toLocaleString()} hit
                    {hunt.lastHitCount === 1 ? "" : "s"}
                  </span>
                ) : (
                  <Muted>never</Muted>
                )}
              </DetailRow>
              <DetailRow label="Owner">
                {hunt.owner?.name ?? <Muted>—</Muted>}
              </DetailRow>
            </dl>
          </Card>

          <Card>
            <CardHeader
              title="Recent alerts"
              hint="raised when a scheduled run finds new matches"
            />
            {hunt.alerts.length === 0 ? (
              <p className="px-4 py-5 text-sm text-ink-muted">No alerts yet.</p>
            ) : (
              <ul className="divide-y divide-line/60">
                {hunt.alerts.map((a) => (
                  <li key={a.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                    <span className="text-sm text-ink">
                      {a.newCount} new
                      <span className="text-ink-faint"> of {a.matchCount}</span>
                    </span>
                    <span className="tabular text-xs text-ink-faint">
                      {a.createdAt.toISOString().slice(0, 16).replace("T", " ")}
                    </span>
                    {a.acknowledged ? (
                      <span className="text-[10px] uppercase tracking-wide text-ink-faint">
                        ack
                      </span>
                    ) : (
                      <span className="rounded bg-warn/15 px-1.5 py-px text-[10px] font-medium text-warn">
                        open
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <div className="lg:col-span-2">
          <Card>
            <CardHeader
              title="Current matches"
              hint={
                preview
                  ? `${preview.total.toLocaleString()} indicator${preview.total === 1 ? "" : "s"} match right now${preview.total > preview.sample.length ? ` · showing ${preview.sample.length}` : ""}`
                  : "query cannot be run"
              }
            />
            {!preview ? (
              <EmptyState
                title="This hunt's query is invalid"
                description={
                  validated.ok ? "" : validated.errors.join(" · ")
                }
                action={
                  canManage ? (
                    <SecondaryLink href={`/hunting/${hunt.id}/edit`}>
                      <Pencil className="size-4" /> Fix it
                    </SecondaryLink>
                  ) : null
                }
              />
            ) : preview.sample.length === 0 ? (
              <EmptyState
                title="Nothing matches yet"
                description="No non-whitelisted indicators match this query right now. If it's scheduled, you'll be alerted when one does."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Type</Th>
                    <Th>Value</Th>
                    <Th>Severity</Th>
                    <Th>Confidence</Th>
                    <Th>Source</Th>
                    <Th>Last seen</Th>
                  </tr>
                </thead>
                <tbody>
                  {preview.sample.map((i) => (
                    <Tr key={i.id} href={`/indicators/${i.id}`}>
                      <Td>
                        <span className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] uppercase text-ink-muted">
                          {i.type}
                        </span>
                      </Td>
                      <Td className="max-w-xs">
                        <Link
                          href={`/indicators/${i.id}`}
                          className="block truncate font-mono text-xs text-ink hover:text-brand"
                          title={i.value}
                        >
                          {i.value}
                        </Link>
                      </Td>
                      <Td>
                        <SeverityBadge severity={i.severity as Severity} />
                      </Td>
                      <Td>
                        <ConfidenceBar value={i.confidence} />
                      </Td>
                      <Td className="text-xs text-ink-muted">
                        {i.sourceName ?? <Muted>manual</Muted>}
                      </Td>
                      <Td className="tabular text-xs text-ink-muted">
                        {i.lastSeen.toISOString().slice(0, 10)}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
