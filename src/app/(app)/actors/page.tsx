import Link from "next/link";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import { Card, ConfidenceBar, EmptyState, TlpBadge } from "@/components/ui/primitives";
import { Pagination, Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, NewButton, PageHeader, Tag } from "@/components/ui/page";
import { ActorFilters } from "./filters";
import { ActorComparePicker } from "./compare-picker";

export const metadata = { title: "Threat Actors · Pulse Intelligence" };

const PAGE_SIZE = 25;

type SearchParams = {
  q?: string;
  motivation?: string;
  active?: string;
  page?: string;
};

export default async function ActorsPage(props: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await props.searchParams;
  const user = await getCurrentUser();
  const page = Math.max(1, Number(params.page) || 1);

  const where = {
    ...(params.q
      ? {
          OR: [
            { name: { contains: params.q, mode: "insensitive" as const } },
            { description: { contains: params.q, mode: "insensitive" as const } },
            {
              aliases: {
                some: { alias: { contains: params.q, mode: "insensitive" as const } },
              },
            },
          ],
        }
      : {}),
    ...(params.motivation ? { motivation: params.motivation as never } : {}),
    ...(params.active === "true"
      ? { active: true }
      : params.active === "false"
        ? { active: false }
        : {}),
  };

  const [actors, total] = await Promise.all([
    db.threatActor.findMany({
      where,
      orderBy: [{ active: "desc" }, { name: "asc" }],
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: {
        aliases: { take: 3, orderBy: { alias: "asc" } },
        _count: { select: { techniques: true, indicators: true, campaigns: true } },
      },
    }),
    db.threatActor.count({ where }),
  ]);

  const filtered = Boolean(params.q || params.motivation || params.active);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Threat Actors"
        description="Tracked APT groups and criminal actors."
        action={
          <div className="flex shrink-0 items-center gap-2">
            <ActorComparePicker actors={actors.map((a) => ({ id: a.id, name: a.name }))} />
            {user && hasRole(user, "ANALYST") ? (
              <NewButton href="/actors/new" label="New actor" />
            ) : null}
          </div>
        }
      />

      <Card>
        <ActorFilters />

        {actors.length === 0 ? (
          <EmptyState
            title={filtered ? "No actors match those filters" : "No threat actors yet"}
            description={
              filtered
                ? "Try widening the search, or clear the filters."
                : "Create one manually, or wait for ATT&CK group import in Phase 3 to populate known APTs."
            }
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Aliases</Th>
                  <Th>Origin</Th>
                  <Th>Motivation</Th>
                  <Th className="text-right">Links</Th>
                  <Th>Confidence</Th>
                  <Th>TLP</Th>
                </tr>
              </thead>
              <tbody>
                {actors.map((actor) => (
                  <Tr key={actor.id} href={`/actors/${actor.id}`}>
                    <Td>
                      <Link
                        href={`/actors/${actor.id}`}
                        className="font-medium text-ink hover:text-brand"
                      >
                        {actor.name}
                      </Link>
                      <div className="mt-0.5 flex items-center gap-1.5">
                        {actor.attackGroupId ? (
                          <span className="font-mono text-[11px] text-ink-faint">
                            {actor.attackGroupId}
                          </span>
                        ) : null}
                        {!actor.active ? (
                          <span className="text-[11px] text-ink-faint">· inactive</span>
                        ) : null}
                      </div>
                    </Td>
                    <Td>
                      {actor.aliases.length ? (
                        <div className="flex flex-wrap gap-1">
                          {actor.aliases.map((a) => (
                            <Tag key={a.id}>{a.alias}</Tag>
                          ))}
                        </div>
                      ) : (
                        <Muted>—</Muted>
                      )}
                    </Td>
                    <Td>{actor.country ?? <Muted>—</Muted>}</Td>
                    <Td>
                      <span className="text-xs text-ink-muted">
                        {actor.motivation.replace("_", " ").toLowerCase()}
                      </span>
                    </Td>
                    <Td className="tabular text-right text-xs text-ink-muted">
                      {actor._count.techniques}T · {actor._count.indicators}I ·{" "}
                      {actor._count.campaigns}C
                    </Td>
                    <Td>
                      <ConfidenceBar value={actor.confidence} />
                    </Td>
                    <Td>
                      <TlpBadge tlp={actor.tlp} />
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
              basePath="/actors"
            />
          </>
        )}
      </Card>
    </div>
  );
}
