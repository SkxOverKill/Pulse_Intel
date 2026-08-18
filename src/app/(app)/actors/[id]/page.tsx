import Link from "next/link";
import { notFound } from "next/navigation";
import { Download, FileCode2, Pencil, Trash2, X } from "lucide-react";
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
import { deleteActor, unlinkTechnique } from "../actions";
import { ActivityTimeline } from "@/components/ui/activity-timeline";
import type { TimelineEvent } from "@/components/ui/activity-timeline";
import { AliasManager } from "./alias-manager";
import { TechniqueMapper } from "./technique-mapper";

export async function generateMetadata(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const actor = await db.threatActor.findUnique({
    where: { id },
    select: { name: true },
  });
  return { title: `${actor?.name ?? "Actor"} · Pulse Intelligence` };
}

const fmt = (d: Date | null) =>
  d ? d.toISOString().slice(0, 10) : null;

export default async function ActorDetailPage(props: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await props.params;
  const user = await getCurrentUser();

  const actor = await db.threatActor.findUnique({
    where: { id },
    include: {
      aliases: {
        orderBy: { alias: "asc" },
        include: { addedBy: { select: { name: true } } },
      },
      techniques: {
        include: { technique: true, addedBy: { select: { name: true } } },
        orderBy: { confidence: "desc" },
      },
      malware: { include: { malware: true } },
      tools: { include: { tool: true } },
      indicators: {
        include: { indicator: true },
        orderBy: { confidence: "desc" },
        take: 25,
      },
      campaigns: { include: { campaign: true } },
      _count: { select: { indicators: true } },
    },
  });

  if (!actor) notFound();

  const canEdit = user && hasRole(user, "ANALYST");
  const canDelete = user && hasRole(user, "ADMIN");

  // Only techniques not already mapped are offered in the picker.
  const techniqueOptions = canEdit
    ? await db.technique.findMany({
        where: {
          deprecated: false,
          id: { notIn: actor.techniques.map((t) => t.techniqueId) },
        },
        select: { id: true, attackId: true, name: true },
        orderBy: { attackId: "asc" },
      })
    : [];

  // Build a chronological event list from all the structured dates on this actor.
  // Order matters: first/last seen anchor the actor's known active window, campaign
  // events show operational tempo, and IOC observations show when intel was collected.
  const timelineEvents: TimelineEvent[] = [];

  if (actor.firstSeen) {
    timelineEvents.push({
      id: "first_seen",
      date: actor.firstSeen.toISOString().slice(0, 10),
      kind: "first_seen",
      label: "Actor first observed",
      note: actor.country ? `Attributed to ${actor.country}` : undefined,
    });
  }

  for (const ca of actor.campaigns) {
    if (ca.campaign.startDate) {
      timelineEvents.push({
        id: `camp_start_${ca.campaignId}`,
        date: ca.campaign.startDate.toISOString().slice(0, 10),
        kind: "campaign_start",
        label: ca.campaign.name,
        href: `/campaigns/${ca.campaignId}`,
        note: ca.campaign.targetSectors.length
          ? `Targeting: ${ca.campaign.targetSectors.slice(0, 3).join(", ")}`
          : undefined,
      });
    }
    if (ca.campaign.endDate) {
      timelineEvents.push({
        id: `camp_end_${ca.campaignId}`,
        date: ca.campaign.endDate.toISOString().slice(0, 10),
        kind: "campaign_end",
        label: `${ca.campaign.name} concluded`,
        href: `/campaigns/${ca.campaignId}`,
      });
    }
  }

  // Sample up to 10 unique indicator observation dates (lastSeen) so the
  // timeline doesn't get swamped by a bulk import that ran on the same day.
  const uniqueIocDates = [
    ...new Map(
      actor.indicators.map((i) => [
        i.indicator.lastSeen.toISOString().slice(0, 10),
        i,
      ])
    ).values(),
  ].slice(0, 10);

  for (const i of uniqueIocDates) {
    timelineEvents.push({
      id: `ioc_${i.indicatorId}`,
      date: i.indicator.lastSeen.toISOString().slice(0, 10),
      kind: "ioc_observed",
      label: `${i.indicator.type} indicator observed`,
      href: `/indicators/${i.indicatorId}`,
      note: i.indicator.value.length > 60
        ? `${i.indicator.value.slice(0, 60)}…`
        : i.indicator.value,
    });
  }

  if (actor.lastSeen) {
    timelineEvents.push({
      id: "last_seen",
      date: actor.lastSeen.toISOString().slice(0, 10),
      kind: "last_seen",
      label: "Most recent confirmed activity",
    });
  }

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title={actor.name}
        description={actor.description ?? undefined}
        action={
          <div className="flex shrink-0 items-center gap-2">
            <a
              href={`/api/sigma/actor/${actor.id}`}
              className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-3 py-2 text-sm text-ink-muted transition-colors hover:text-ink"
              title="Download Sigma detection rules for this actor"
            >
              <FileCode2 className="size-4" />
              Sigma rules
            </a>
            {canEdit ? (
              <SecondaryLink href={`/actors/${actor.id}/edit`}>
                <Pencil className="size-4" />
                Edit
              </SecondaryLink>
            ) : null}
            {canDelete ? (
              <form action={deleteActor}>
                <input type="hidden" name="id" value={actor.id} />
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
            <CardHeader title="Profile" />
            <dl>
              <DetailRow label="Status">
                {actor.active ? (
                  <span className="text-ok">Active</span>
                ) : (
                  <Muted>Inactive</Muted>
                )}
              </DetailRow>
              <DetailRow label="ATT&CK group">
                {actor.attackGroupId ? (
                  <span className="font-mono text-xs">{actor.attackGroupId}</span>
                ) : (
                  <Muted>Not tracked by MITRE</Muted>
                )}
              </DetailRow>
              <DetailRow label="Origin">{actor.country ?? <Muted>Unknown</Muted>}</DetailRow>
              <DetailRow label="Motivation">
                {actor.motivation.replace("_", " ").toLowerCase()}
              </DetailRow>
              <DetailRow label="Sophistication">
                {actor.sophistication?.toLowerCase() ?? <Muted>Not assessed</Muted>}
              </DetailRow>
              <DetailRow label="First seen">
                {fmt(actor.firstSeen) ?? <Muted>Unknown</Muted>}
              </DetailRow>
              <DetailRow label="Last seen">
                {fmt(actor.lastSeen) ?? <Muted>Unknown</Muted>}
              </DetailRow>
              <DetailRow label="Confidence">
                <ConfidenceBar value={actor.confidence} />
              </DetailRow>
              <DetailRow label="TLP">
                <TlpBadge tlp={actor.tlp} />
              </DetailRow>
            </dl>
          </Card>

          <Card>
            <CardHeader title="Targeting" />
            <dl>
              <DetailRow label="Sectors">
                {actor.targetSectors.length ? (
                  <div className="flex flex-wrap gap-1">
                    {actor.targetSectors.map((s) => (
                      <Tag key={s}>{s}</Tag>
                    ))}
                  </div>
                ) : (
                  <Muted>Not recorded</Muted>
                )}
              </DetailRow>
              <DetailRow label="Countries">
                {actor.targetCountries.length ? (
                  <div className="flex flex-wrap gap-1">
                    {actor.targetCountries.map((c) => (
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
              title="Aliases"
              hint="Cross-vendor names. Attribution is recorded, never collapsed."
            />
            <AliasManager
              actorId={actor.id}
              aliases={actor.aliases.map((a) => ({
                id: a.id,
                alias: a.alias,
                namedBy: a.namedBy,
                addedBy: a.addedBy?.name ?? null,
              }))}
              canEdit={Boolean(canEdit)}
            />
          </Card>

          <Card>
            <CardHeader
              title="ATT&CK techniques"
              hint={`${actor.techniques.length} mapped`}
              action={
                actor.techniques.length > 0 ? (
                  <a
                    href={`/api/attack/navigator?domain=ENTERPRISE&actorId=${actor.id}`}
                    className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-2.5 py-1 text-xs text-ink-muted transition-colors hover:text-ink"
                  >
                    <Download className="size-3.5" />
                    Navigator layer
                  </a>
                ) : null
              }
            />
            {actor.techniques.length === 0 ? (
              <EmptyState
                title="No techniques mapped"
                description="Map techniques by hand below, or run `npm run attack:sync` to import MITRE's own attribution for this group."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>ID</Th>
                    <Th>Technique</Th>
                    <Th>Tactics</Th>
                    <Th>Confidence</Th>
                    <Th>Claimed by</Th>
                    <Th />
                  </tr>
                </thead>
                <tbody>
                  {actor.techniques.map((t) => (
                    <Tr key={t.techniqueId}>
                      <Td className="font-mono text-xs">
                        <Link
                          href={`/attack/${t.technique.attackId}`}
                          className="text-ink hover:text-brand"
                        >
                          {t.technique.attackId}
                        </Link>
                      </Td>
                      <Td>{t.technique.name}</Td>
                      <Td className="text-xs text-ink-muted">
                        {t.technique.tactics.join(", ") || <Muted>—</Muted>}
                      </Td>
                      <Td>
                        <ConfidenceBar value={t.confidence} />
                      </Td>
                      <Td className="text-xs text-ink-muted">
                        {/* Imported ATT&CK mappings have no addedBy — they are
                            MITRE's claim, not an analyst's. */}
                        {t.addedBy?.name ?? (t.notes ? "MITRE ATT&CK" : <Muted>—</Muted>)}
                      </Td>
                      <Td>
                        {canEdit ? (
                          <form action={unlinkTechnique}>
                            <input type="hidden" name="actorId" value={actor.id} />
                            <input
                              type="hidden"
                              name="techniqueId"
                              value={t.techniqueId}
                            />
                            <button
                              type="submit"
                              title={`Unmap ${t.technique.attackId}`}
                              className="grid size-6 place-items-center rounded text-ink-faint hover:bg-surface-2 hover:text-danger"
                            >
                              <X className="size-3.5" />
                            </button>
                          </form>
                        ) : null}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
            {canEdit ? (
              <TechniqueMapper actorId={actor.id} options={techniqueOptions} />
            ) : null}
          </Card>

          <Card>
            <CardHeader
              title="Malware & tools"
              hint={`${actor.malware.length} malware · ${actor.tools.length} tools`}
            />
            {actor.malware.length === 0 && actor.tools.length === 0 ? (
              <EmptyState
                title="No software linked"
                description="Run `npm run attack:sync` to import MITRE's software attribution for this group."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Type</Th>
                    <Th>Software</Th>
                    <Th>Confidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {actor.malware.map((m) => (
                    <Tr key={m.malwareId}>
                      <Td className="text-xs text-ink-muted">Malware</Td>
                      <Td>
                        <Link
                          href={`/malware/${m.malwareId}`}
                          className="font-medium text-ink hover:text-brand"
                        >
                          {m.malware.name}
                        </Link>
                      </Td>
                      <Td>
                        <ConfidenceBar value={m.confidence} />
                      </Td>
                    </Tr>
                  ))}
                  {actor.tools.map((t) => (
                    <Tr key={t.toolId}>
                      <Td className="text-xs text-ink-muted">Tool</Td>
                      <Td>
                        <Link
                          href={`/malware/${t.toolId}`}
                          className="font-medium text-ink hover:text-brand"
                        >
                          {t.tool.name}
                        </Link>
                      </Td>
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
              title="Indicators"
              hint={`${actor._count.indicators} linked`}
            />
            {actor.indicators.length === 0 ? (
              <EmptyState
                title="No indicators linked"
                description="Link IOCs from the indicator detail page, or ingest them via a feed in Phase 5."
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
                  {actor.indicators.map((i) => (
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

          {timelineEvents.length > 0 ? (
            <Card>
              <CardHeader
                title="Activity timeline"
                hint="Chronological record of campaigns, IOC observations, and confirmed activity windows"
              />
              <ActivityTimeline events={timelineEvents} />
            </Card>
          ) : null}

          <Card>
            <CardHeader title="Campaigns" hint={`${actor.campaigns.length} linked`} />
            {actor.campaigns.length === 0 ? (
              <EmptyState
                title="No campaigns linked"
                description="Link this actor from a campaign's detail page."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Campaign</Th>
                    <Th>Status</Th>
                    <Th>Attribution confidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {actor.campaigns.map((c) => (
                    <Tr key={c.campaignId}>
                      <Td>
                        <Link
                          href={`/campaigns/${c.campaignId}`}
                          className="text-ink hover:text-brand"
                        >
                          {c.campaign.name}
                        </Link>
                      </Td>
                      <Td className="text-xs text-ink-muted">
                        {c.campaign.status.toLowerCase()}
                      </Td>
                      <Td>
                        <ConfidenceBar value={c.confidence} />
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
