import Link from "next/link";
import { notFound } from "next/navigation";
import { FileCode2, Pencil, Trash2 } from "lucide-react";
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
import { deleteCampaign } from "../actions";
import { AttributionPanel } from "./attribution-panel";

export async function generateMetadata(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const c = await db.campaign.findUnique({ where: { id }, select: { name: true } });
  return { title: `${c?.name ?? "Campaign"} · Pulse Intelligence` };
}

const fmt = (d: Date | null) => (d ? d.toISOString().slice(0, 10) : null);

export default async function CampaignDetailPage(props: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await props.params;
  const user = await getCurrentUser();

  const campaign = await db.campaign.findUnique({
    where: { id },
    include: {
      actors: {
        include: {
          actor: { select: { id: true, name: true, country: true } },
          addedBy: { select: { name: true } },
        },
        orderBy: { confidence: "desc" },
      },
      indicators: { include: { indicator: true }, take: 25 },
      techniques: { include: { technique: true } },
      _count: { select: { indicators: true } },
    },
  });

  if (!campaign) notFound();

  const relatedNews = await db.newsItem.findMany({
    where: { linkedCampaignIds: { has: campaign.id } },
    orderBy: { publishedAt: "desc" },
    take: 10,
    include: { source: { select: { name: true } } },
  });

  const canEdit = user && hasRole(user, "ANALYST");
  const canDelete = user && hasRole(user, "ADMIN");

  // Only actors not already attributed are offered in the picker.
  const availableActors = canEdit
    ? await db.threatActor.findMany({
        where: { id: { notIn: campaign.actors.map((a) => a.actorId) } },
        select: { id: true, name: true },
        orderBy: { name: "asc" },
      })
    : [];

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title={campaign.name}
        description={campaign.description ?? undefined}
        action={
          <div className="flex shrink-0 items-center gap-2">
            <a
              href={`/api/sigma/campaign/${campaign.id}`}
              className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-3 py-2 text-sm text-ink-muted transition-colors hover:text-ink"
              title="Download Sigma detection rules for this campaign"
            >
              <FileCode2 className="size-4" />
              Sigma rules
            </a>
            {canEdit ? (
              <SecondaryLink href={`/campaigns/${campaign.id}/edit`}>
                <Pencil className="size-4" />
                Edit
              </SecondaryLink>
            ) : null}
            {canDelete ? (
              <form action={deleteCampaign}>
                <input type="hidden" name="id" value={campaign.id} />
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
        <div className="space-y-4 lg:col-span-1">
          <Card>
            <CardHeader title="Campaign" />
            <dl>
              <DetailRow label="Status">{campaign.status.toLowerCase()}</DetailRow>
              <DetailRow label="Started">
                {fmt(campaign.startDate) ?? <Muted>Unknown</Muted>}
              </DetailRow>
              <DetailRow label="Ended">
                {fmt(campaign.endDate) ?? <Muted>Ongoing</Muted>}
              </DetailRow>
              <DetailRow label="Confidence">
                <ConfidenceBar value={campaign.confidence} />
              </DetailRow>
              <DetailRow label="TLP">
                <TlpBadge tlp={campaign.tlp} />
              </DetailRow>
              <DetailRow label="Sectors">
                {campaign.targetSectors.length ? (
                  <div className="flex flex-wrap gap-1">
                    {campaign.targetSectors.map((s) => (
                      <Tag key={s}>{s}</Tag>
                    ))}
                  </div>
                ) : (
                  <Muted>Not recorded</Muted>
                )}
              </DetailRow>
              <DetailRow label="Countries">
                {campaign.targetCountries.length ? (
                  <div className="flex flex-wrap gap-1">
                    {campaign.targetCountries.map((c) => (
                      <Tag key={c}>{c}</Tag>
                    ))}
                  </div>
                ) : (
                  <Muted>Not recorded</Muted>
                )}
              </DetailRow>
            </dl>
          </Card>
        </div>

        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader
              title="Attribution"
              hint="Who is believed to be behind this, and how strongly"
            />
            <AttributionPanel
              campaignId={campaign.id}
              attributions={campaign.actors.map((a) => ({
                actorId: a.actorId,
                name: a.actor.name,
                country: a.actor.country,
                confidence: a.confidence,
                addedBy: a.addedBy?.name ?? null,
              }))}
              availableActors={availableActors}
              canEdit={Boolean(canEdit)}
            />
          </Card>

          <Card>
            <CardHeader title="Indicators" hint={`${campaign._count.indicators} linked`} />
            {campaign.indicators.length === 0 ? (
              <EmptyState
                title="No indicators linked"
                description="Link IOCs observed in this campaign to build its fingerprint."
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
                  {campaign.indicators.map((i) => (
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

          <Card>
            <CardHeader title="ATT&CK techniques" hint={`${campaign.techniques.length} mapped`} />
            {campaign.techniques.length === 0 ? (
              <EmptyState
                title="No techniques mapped"
                description="Technique mapping arrives with the ATT&CK matrix in Phase 3."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>ID</Th>
                    <Th>Technique</Th>
                    <Th>Confidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {campaign.techniques.map((t) => (
                    <Tr key={t.techniqueId}>
                      <Td className="font-mono text-xs">{t.technique.attackId}</Td>
                      <Td>{t.technique.name}</Td>
                      <Td>
                        <ConfidenceBar value={t.confidence} />
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>

          <Card>
            <CardHeader
              title="Related news"
              hint="Auto-linked by campaign name — updates as new articles come in"
            />
            {relatedNews.length === 0 ? (
              <EmptyState
                title="No linked coverage yet"
                description="News mentioning this campaign by name links here automatically as the feeds run."
              />
            ) : (
              <ul className="divide-y divide-line/60">
                {relatedNews.map((n) => (
                  <li key={n.id} className="px-4 py-2.5">
                    <a
                      href={n.url}
                      target="_blank"
                      rel="noopener noreferrer nofollow"
                      className="block truncate text-sm text-ink hover:text-brand"
                    >
                      {n.title}
                    </a>
                    <p className="mt-0.5 text-[11px] text-ink-faint">
                      {n.source?.name ?? "unknown"} · {n.publishedAt.toISOString().slice(0, 10)}
                    </p>
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
