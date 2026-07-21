import Link from "next/link";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import { Card, ConfidenceBar, EmptyState, TlpBadge } from "@/components/ui/primitives";
import { Pagination, Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, NewButton, PageHeader, Tag } from "@/components/ui/page";

export const metadata = { title: "Campaigns · Pulse Intelligence" };

const PAGE_SIZE = 25;

const STATUS_TONE: Record<string, string> = {
  ACTIVE: "text-ok",
  SUSPECTED: "text-warn",
  DORMANT: "text-ink-muted",
  CONCLUDED: "text-ink-faint",
};

export default async function CampaignsPage(props: {
  searchParams: Promise<{ status?: string; page?: string }>;
}) {
  const params = await props.searchParams;
  const user = await getCurrentUser();
  const page = Math.max(1, Number(params.page) || 1);

  const where = params.status ? { status: params.status as never } : {};

  const [campaigns, total] = await Promise.all([
    db.campaign.findMany({
      where,
      orderBy: [{ startDate: "desc" }, { name: "asc" }],
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: {
        actors: { include: { actor: { select: { id: true, name: true } } }, take: 3 },
        _count: { select: { indicators: true, techniques: true } },
      },
    }),
    db.campaign.count({ where }),
  ]);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Campaigns"
        description="Tracked operations, and who is believed to be behind them."
        action={
          user && hasRole(user, "ANALYST") ? (
            <NewButton href="/campaigns/new" label="New campaign" />
          ) : null
        }
      />

      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
          {[
            { value: "", label: "All" },
            { value: "ACTIVE", label: "Active" },
            { value: "SUSPECTED", label: "Suspected" },
            { value: "DORMANT", label: "Dormant" },
            { value: "CONCLUDED", label: "Concluded" },
          ].map((f) => {
            const active = (params.status ?? "") === f.value;
            return (
              <Link
                key={f.value || "all"}
                href={f.value ? `/campaigns?status=${f.value}` : "/campaigns"}
                className={`rounded-md px-2.5 py-1.5 text-sm transition-colors ${
                  active
                    ? "bg-brand/15 text-ink"
                    : "text-ink-muted hover:bg-surface-2 hover:text-ink"
                }`}
              >
                {f.label}
              </Link>
            );
          })}
        </div>

        {campaigns.length === 0 ? (
          <EmptyState
            title="No campaigns yet"
            description="A campaign groups related activity over time. Create one, then attribute it to an actor once you have the confidence to."
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Campaign</Th>
                  <Th>Status</Th>
                  <Th>Attributed to</Th>
                  <Th>Period</Th>
                  <Th>Targets</Th>
                  <Th className="text-right">Links</Th>
                  <Th>Confidence</Th>
                  <Th>TLP</Th>
                </tr>
              </thead>
              <tbody>
                {campaigns.map((c) => (
                  <Tr key={c.id} href={`/campaigns/${c.id}`}>
                    <Td>
                      <Link
                        href={`/campaigns/${c.id}`}
                        className="font-medium text-ink hover:text-brand"
                      >
                        {c.name}
                      </Link>
                    </Td>
                    <Td>
                      <span className={`text-xs ${STATUS_TONE[c.status]}`}>
                        {c.status.toLowerCase()}
                      </span>
                    </Td>
                    <Td>
                      {c.actors.length ? (
                        <div className="flex flex-wrap gap-1">
                          {c.actors.map((a) => (
                            <Link
                              key={a.actorId}
                              href={`/actors/${a.actorId}`}
                              className="rounded border border-line bg-surface-2 px-1.5 py-0.5 text-xs text-ink-muted hover:text-brand"
                            >
                              {a.actor.name}
                            </Link>
                          ))}
                        </div>
                      ) : (
                        <Muted>unattributed</Muted>
                      )}
                    </Td>
                    <Td className="tabular text-xs text-ink-muted">
                      {c.startDate ? c.startDate.toISOString().slice(0, 10) : "—"}
                      {c.endDate ? ` → ${c.endDate.toISOString().slice(0, 10)}` : ""}
                    </Td>
                    <Td>
                      {c.targetSectors.length ? (
                        <div className="flex flex-wrap gap-1">
                          {c.targetSectors.slice(0, 2).map((s) => (
                            <Tag key={s}>{s}</Tag>
                          ))}
                        </div>
                      ) : (
                        <Muted>—</Muted>
                      )}
                    </Td>
                    <Td className="tabular text-right text-xs text-ink-muted">
                      {c._count.indicators}I · {c._count.techniques}T
                    </Td>
                    <Td>
                      <ConfidenceBar value={c.confidence} />
                    </Td>
                    <Td>
                      <TlpBadge tlp={c.tlp} />
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
              basePath="/campaigns"
            />
          </>
        )}
      </Card>
    </div>
  );
}
