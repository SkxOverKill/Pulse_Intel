import Link from "next/link";
import { ExternalLink } from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { Pagination } from "@/components/ui/table";
import { PageHeader, Tag } from "@/components/ui/page";

export const metadata = { title: "Threat News · Pulse Intelligence" };

const PAGE_SIZE = 30;

export default async function NewsPage(props: {
  searchParams: Promise<{ page?: string; sort?: string }>;
}) {
  await requireUser();
  const params = await props.searchParams;
  const page = Math.max(1, Number(params.page) || 1);
  const byRelevance = params.sort === "relevance";

  const [items, total] = await Promise.all([
    db.newsItem.findMany({
      orderBy: byRelevance
        ? [{ relevanceScore: "desc" }, { publishedAt: "desc" }]
        : { publishedAt: "desc" },
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: { source: { select: { name: true } } },
    }),
    db.newsItem.count(),
  ]);

  // Resolve linked actor names in one query rather than per-item.
  const actorIds = [...new Set(items.flatMap((i) => i.linkedActorIds))];
  const actors = actorIds.length
    ? await db.threatActor.findMany({
        where: { id: { in: actorIds } },
        select: { id: true, name: true },
      })
    : [];
  const actorName = new Map(actors.map((a) => [a.id, a.name]));

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Threat News"
        description="Aggregated from vendor research blogs and government advisories, auto-linked to tracked actors and CVEs."
      />

      <div className="mb-4 flex items-center gap-2">
        <Link
          href="/news"
          className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
            !byRelevance
              ? "bg-brand/15 text-ink"
              : "border border-line bg-surface text-ink-muted hover:text-ink"
          }`}
        >
          Latest
        </Link>
        <Link
          href="/news?sort=relevance"
          className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
            byRelevance
              ? "bg-brand/15 text-ink"
              : "border border-line bg-surface text-ink-muted hover:text-ink"
          }`}
        >
          Most relevant
        </Link>
      </div>

      {items.length === 0 ? (
        <Card>
          <EmptyState
            title="No news yet"
            description="Run the worker (`npm run worker -- --run-now`) to pull from the configured RSS sources."
          />
        </Card>
      ) : (
        <>
          <div className="space-y-2">
            {items.map((item) => (
              <Card key={item.id} className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noopener noreferrer nofollow"
                      className="group inline-flex items-start gap-1.5 text-sm font-medium text-ink hover:text-brand"
                    >
                      {item.title}
                      <ExternalLink className="mt-0.5 size-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
                    </a>

                    {item.summary ? (
                      <p className="mt-1 line-clamp-2 text-xs text-ink-muted">
                        {item.summary}
                      </p>
                    ) : null}

                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <span className="text-[11px] text-ink-faint">
                        {item.source?.name ?? "unknown"} ·{" "}
                        {item.publishedAt.toISOString().slice(0, 10)}
                      </span>

                      {item.linkedActorIds.map((id) => (
                        <Link
                          key={id}
                          href={`/actors/${id}`}
                          className="rounded border border-brand/40 bg-brand/10 px-1.5 py-0.5 text-[11px] text-brand hover:bg-brand/20"
                        >
                          {actorName.get(id) ?? "actor"}
                        </Link>
                      ))}

                      {item.linkedCveIds.slice(0, 4).map((cve) => (
                        <Link
                          key={cve}
                          href={`/vulnerabilities/${cve}`}
                          className="rounded border border-sev-high/40 bg-sev-high/10 px-1.5 py-0.5 font-mono text-[11px] text-sev-high hover:bg-sev-high/20"
                        >
                          {cve}
                        </Link>
                      ))}
                      {item.linkedCveIds.length > 4 ? (
                        <Tag>+{item.linkedCveIds.length - 4} more</Tag>
                      ) : null}
                    </div>
                  </div>

                  {item.relevanceScore > 0 ? (
                    <span
                      className="tabular shrink-0 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-ink-muted"
                      title="Relevance: 25 per linked actor, 15 per CVE"
                    >
                      {item.relevanceScore}
                    </span>
                  ) : null}
                </div>
              </Card>
            ))}
          </div>

          <div className="mt-4 rounded-[--radius-card] border border-line bg-surface">
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              total={total}
              searchParams={params}
              basePath="/news"
            />
          </div>
        </>
      )}
    </div>
  );
}
