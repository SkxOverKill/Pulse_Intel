import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink, Shield } from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import {
  Card,
  CardHeader,
  ConfidenceBar,
  EmptyState,
} from "@/components/ui/primitives";
import { DetailRow, Muted, PageHeader, Tag } from "@/components/ui/page";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { getCountermeasures, DEFEND_CATEGORY_COLORS } from "@/lib/defend/countermeasures";

export async function generateMetadata(props: {
  params: Promise<{ attackId: string }>;
}) {
  const { attackId } = await props.params;
  const t = await db.technique.findFirst({
    where: { attackId: decodeURIComponent(attackId) },
    select: { name: true, attackId: true },
  });
  return {
    title: t ? `${t.attackId} ${t.name} · Pulse Intelligence` : "Technique",
  };
}

export default async function TechniquePage(props: {
  params: Promise<{ attackId: string }>;
}) {
  await requireUser();
  const { attackId: raw } = await props.params;
  const attackId = decodeURIComponent(raw);

  const technique = await db.technique.findFirst({
    where: { attackId },
    include: {
      parent: { select: { attackId: true, name: true } },
      subtechniques: {
        where: { deprecated: false },
        orderBy: { attackId: "asc" },
        select: { id: true, attackId: true, name: true },
      },
      actors: {
        include: {
          actor: { select: { id: true, name: true, country: true } },
          addedBy: { select: { name: true } },
        },
        orderBy: { confidence: "desc" },
      },
      campaigns: {
        include: { campaign: { select: { id: true, name: true } } },
      },
    },
  });

  if (!technique) notFound();

  const tactics = await db.tactic.findMany({
    where: { domain: technique.domain, shortname: { in: technique.tactics } },
    orderBy: { order: "asc" },
  });

  const countermeasures = getCountermeasures(technique.attackId);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title={`${technique.attackId} · ${technique.name}`}
        description={
          technique.parent
            ? `Sub-technique of ${technique.parent.attackId} ${technique.parent.name}`
            : undefined
        }
        action={
          <a
            href={`https://attack.mitre.org/techniques/${technique.attackId.replace(".", "/")}/`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
          >
            View on attack.mitre.org
            <ExternalLink className="size-3.5" />
          </a>
        }
      />

      {technique.deprecated ? (
        <div className="mb-4 rounded-[--radius-card] border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-warn">
          This technique is deprecated in ATT&CK v{technique.attackVersion}. Existing
          mappings are preserved, but prefer a current technique for new work.
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Description" />
            {technique.description ? (
              <div className="whitespace-pre-wrap px-4 py-4 text-sm leading-relaxed text-ink">
                {technique.description}
              </div>
            ) : (
              <p className="px-4 py-4 text-sm text-ink-faint">No description.</p>
            )}
          </Card>

          <Card>
            <CardHeader
              title="Detection"
              hint="Composed from ATT&CK detection strategies and analytics"
            />
            {technique.detection ? (
              <div className="whitespace-pre-wrap px-4 py-4 text-sm leading-relaxed text-ink">
                {technique.detection}
              </div>
            ) : (
              <p className="px-4 py-4 text-sm text-ink-faint">
                No detection guidance published for this technique.
              </p>
            )}
          </Card>

          {countermeasures.length > 0 ? (
            <Card>
              <CardHeader
                title="D3FEND countermeasures"
                hint="MITRE D3FEND defensive techniques mapped to this attack"
                action={
                  <a
                    href={`https://d3fend.mitre.org/offensive-technique/attack:${technique.attackId}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] text-ink-muted hover:text-brand"
                  >
                    D3FEND <ExternalLink className="size-3" />
                  </a>
                }
              />
              <div className="divide-y divide-line/60">
                {countermeasures.map((cm) => {
                  const color = DEFEND_CATEGORY_COLORS[cm.category] ?? "bg-surface-2 text-ink-muted border-line";
                  return (
                    <div key={cm.d3fend_id} className="flex items-start gap-3 px-4 py-3">
                      <Shield className="mt-0.5 size-4 shrink-0 text-ink-muted" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium text-ink">{cm.label}</span>
                          <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${color}`}>
                            {cm.category}
                          </span>
                          <span className="font-mono text-[10px] text-ink-faint">{cm.d3fend_id}</span>
                        </div>
                        <p className="mt-0.5 text-xs text-ink-muted">{cm.definition}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          ) : null}

          <Card>
            <CardHeader
              title="Tracked actors using this"
              hint={`${technique.actors.length} mapped`}
            />
            {technique.actors.length === 0 ? (
              <EmptyState
                title="No tracked actors mapped"
                description="Either none of your tracked actors use this, or the mapping has not been recorded yet."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Actor</Th>
                    <Th>Origin</Th>
                    <Th>Confidence</Th>
                    <Th>Source</Th>
                  </tr>
                </thead>
                <tbody>
                  {technique.actors.map((a) => (
                    <Tr key={a.actorId}>
                      <Td>
                        <Link
                          href={`/actors/${a.actorId}`}
                          className="text-ink hover:text-brand"
                        >
                          {a.actor.name}
                        </Link>
                      </Td>
                      <Td className="text-xs text-ink-muted">
                        {a.actor.country ?? <Muted>—</Muted>}
                      </Td>
                      <Td>
                        <ConfidenceBar value={a.confidence} />
                      </Td>
                      <Td className="text-xs text-ink-muted">
                        {a.addedBy?.name ?? (a.notes ? "MITRE ATT&CK" : <Muted>—</Muted>)}
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
            <CardHeader title="Technique" />
            <dl>
              <DetailRow label="ATT&CK ID">
                <span className="font-mono text-xs">{technique.attackId}</span>
              </DetailRow>
              <DetailRow label="Domain">{technique.domain.toLowerCase()}</DetailRow>
              <DetailRow label="Tactics">
                {tactics.length ? (
                  <div className="flex flex-wrap gap-1">
                    {tactics.map((t) => (
                      <Link
                        key={t.id}
                        href={`/attack?domain=${technique.domain}`}
                        className="rounded border border-line bg-surface-2 px-1.5 py-0.5 text-xs text-ink-muted hover:text-brand"
                      >
                        {t.name}
                      </Link>
                    ))}
                  </div>
                ) : (
                  <Muted>None</Muted>
                )}
              </DetailRow>
              <DetailRow label="Platforms">
                {technique.platforms.length ? (
                  <div className="flex flex-wrap gap-1">
                    {technique.platforms.map((p) => (
                      <Tag key={p}>{p}</Tag>
                    ))}
                  </div>
                ) : (
                  <Muted>Not specified</Muted>
                )}
              </DetailRow>
              <DetailRow label="Data sources">
                {technique.dataSources.length ? (
                  <div className="flex flex-wrap gap-1">
                    {technique.dataSources.map((d) => (
                      <Tag key={d}>{d}</Tag>
                    ))}
                  </div>
                ) : (
                  <Muted>None listed</Muted>
                )}
              </DetailRow>
              <DetailRow label="ATT&CK version">
                <span className="tabular text-xs">v{technique.attackVersion}</span>
              </DetailRow>
            </dl>
          </Card>

          {technique.subtechniques.length > 0 ? (
            <Card>
              <CardHeader
                title="Sub-techniques"
                hint={`${technique.subtechniques.length}`}
              />
              <ul className="divide-y divide-line/60">
                {technique.subtechniques.map((s) => (
                  <li key={s.id}>
                    <Link
                      href={`/attack/${s.attackId}`}
                      className="block px-4 py-2 hover:bg-surface-2"
                    >
                      <span className="block text-sm text-ink">{s.name}</span>
                      <span className="tabular block text-[11px] text-ink-faint">
                        {s.attackId}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}

          {technique.campaigns.length > 0 ? (
            <Card>
              <CardHeader title="Campaigns" />
              <ul className="divide-y divide-line/60">
                {technique.campaigns.map((c) => (
                  <li key={c.campaignId} className="px-4 py-2">
                    <Link
                      href={`/campaigns/${c.campaignId}`}
                      className="text-sm text-ink hover:text-brand"
                    >
                      {c.campaign.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}
        </div>
      </div>
    </div>
  );
}
