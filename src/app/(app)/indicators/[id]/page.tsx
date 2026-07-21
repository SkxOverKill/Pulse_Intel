import Link from "next/link";
import { notFound } from "next/navigation";
import { ShieldOff, Trash2 } from "lucide-react";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import {
  Card,
  CardHeader,
  ConfidenceBar,
  EmptyState,
  SeverityBadge,
  TlpBadge,
} from "@/components/ui/primitives";
import { DetailRow, Muted, PageHeader, Tag } from "@/components/ui/page";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { defang } from "@/lib/ioc/normalize";
import { whitelistReason } from "@/lib/ioc/whitelist";
import { deleteIndicator, setWhitelisted } from "../actions";

export async function generateMetadata(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const i = await db.indicator.findUnique({ where: { id }, select: { value: true } });
  return { title: `${i?.value ?? "Indicator"} · Pulse Intelligence` };
}

export default async function IndicatorDetailPage(props: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await props.params;
  const user = await getCurrentUser();

  const indicator = await db.indicator.findUnique({
    where: { id },
    include: {
      source: true,
      enrichments: { orderBy: { fetchedAt: "desc" } },
      actors: { include: { actor: true } },
      campaigns: { include: { campaign: true } },
      reports: { include: { report: true } },
    },
  });

  if (!indicator) notFound();

  const canEdit = user && hasRole(user, "ANALYST");
  const canDelete = user && hasRole(user, "ADMIN");
  const autoReason = whitelistReason(indicator.type, indicator.normalizedValue);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title={indicator.value}
        description={`${indicator.type} · first seen ${indicator.firstSeen.toISOString().slice(0, 10)}`}
        action={
          <div className="flex shrink-0 items-center gap-2">
            {canEdit ? (
              <form action={setWhitelisted}>
                <input type="hidden" name="id" value={indicator.id} />
                <input
                  type="hidden"
                  name="whitelisted"
                  value={indicator.whitelisted ? "" : "true"}
                />
                <button
                  type="submit"
                  className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
                >
                  <ShieldOff className="size-4" />
                  {indicator.whitelisted ? "Remove from whitelist" : "Whitelist"}
                </button>
              </form>
            ) : null}
            {canDelete ? (
              <form action={deleteIndicator}>
                <input type="hidden" name="id" value={indicator.id} />
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

      {indicator.whitelisted ? (
        <div className="mb-4 flex items-start gap-2 rounded-[--radius-card] border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-warn">
          <ShieldOff className="mt-0.5 size-4 shrink-0" />
          <div>
            <p className="font-medium">Whitelisted — excluded from exports and alerting.</p>
            <p className="mt-0.5 text-xs opacity-90">
              {autoReason ?? "Manually whitelisted by an analyst."}
            </p>
          </div>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-1">
          <Card>
            <CardHeader title="Indicator" />
            <dl>
              <DetailRow label="Type">
                <span className="font-mono text-xs">{indicator.type}</span>
              </DetailRow>
              <DetailRow label="Value">
                <span className="break-all font-mono text-xs">{indicator.value}</span>
              </DetailRow>
              <DetailRow label="Normalized">
                <span className="break-all font-mono text-xs text-ink-muted">
                  {indicator.normalizedValue}
                </span>
              </DetailRow>
              <DetailRow label="Defanged">
                {/* Safe to copy into a ticket or email without creating a live link. */}
                <span className="break-all font-mono text-xs text-ink-muted">
                  {defang(indicator.value)}
                </span>
              </DetailRow>
              <DetailRow label="Severity">
                <SeverityBadge severity={indicator.severity} />
              </DetailRow>
              <DetailRow label="Confidence">
                <ConfidenceBar value={indicator.confidence} />
              </DetailRow>
              <DetailRow label="TLP">
                <TlpBadge tlp={indicator.tlp} />
              </DetailRow>
              <DetailRow label="Source">
                {indicator.source?.name ?? <Muted>Manual entry</Muted>}
              </DetailRow>
              <DetailRow label="First seen">
                {indicator.firstSeen.toISOString().slice(0, 10)}
              </DetailRow>
              <DetailRow label="Last seen">
                {indicator.lastSeen.toISOString().slice(0, 10)}
              </DetailRow>
              <DetailRow label="Tags">
                {indicator.tags.length ? (
                  <div className="flex flex-wrap gap-1">
                    {indicator.tags.map((t) => (
                      <Tag key={t}>{t}</Tag>
                    ))}
                  </div>
                ) : (
                  <Muted>None</Muted>
                )}
              </DetailRow>
            </dl>
          </Card>
        </div>

        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader
              title="Enrichment"
              hint="Provider lookups, cached until they expire"
            />
            {indicator.enrichments.length === 0 ? (
              <EmptyState
                title="Not enriched yet"
                description="The enrichment engine — VirusTotal, AbuseIPDB, OTX behind a shared rate limiter — arrives in Phase 4."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Provider</Th>
                    <Th>Verdict</Th>
                    <Th>Score</Th>
                    <Th>Fetched</Th>
                    <Th>Expires</Th>
                  </tr>
                </thead>
                <tbody>
                  {indicator.enrichments.map((e) => (
                    <Tr key={e.id}>
                      <Td className="text-xs">{e.provider}</Td>
                      <Td className="text-xs">{e.verdict}</Td>
                      <Td className="tabular text-xs">{e.score ?? "—"}</Td>
                      <Td className="tabular text-xs text-ink-muted">
                        {e.fetchedAt.toISOString().slice(0, 10)}
                      </Td>
                      <Td className="tabular text-xs text-ink-muted">
                        {e.expiresAt.toISOString().slice(0, 10)}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>

          <Card>
            <CardHeader title="Attributed to" hint="Actors and campaigns linked to this indicator" />
            {indicator.actors.length === 0 && indicator.campaigns.length === 0 ? (
              <EmptyState
                title="No attribution"
                description="Link this indicator to an actor or campaign to record who is believed to use it."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Kind</Th>
                    <Th>Name</Th>
                    <Th>Confidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {indicator.actors.map((a) => (
                    <Tr key={`a-${a.actorId}`}>
                      <Td className="text-xs text-ink-muted">Actor</Td>
                      <Td>
                        <Link
                          href={`/actors/${a.actorId}`}
                          className="text-ink hover:text-brand"
                        >
                          {a.actor.name}
                        </Link>
                      </Td>
                      <Td>
                        <ConfidenceBar value={a.confidence} />
                      </Td>
                    </Tr>
                  ))}
                  {indicator.campaigns.map((c) => (
                    <Tr key={`c-${c.campaignId}`}>
                      <Td className="text-xs text-ink-muted">Campaign</Td>
                      <Td>
                        <Link
                          href={`/campaigns/${c.campaignId}`}
                          className="text-ink hover:text-brand"
                        >
                          {c.campaign.name}
                        </Link>
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
