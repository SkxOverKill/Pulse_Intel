import Link from "next/link";
import {
  Database,
  FileText,
  Newspaper,
  Radar,
  Rss,
  ShieldAlert,
  Target,
  Users,
} from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";

export const metadata = { title: "Dashboard · Pulse Intelligence" };

/**
 * Counts are fetched sequentially rather than with Promise.all: the local dev
 * Postgres drops connections under concurrent load (see src/lib/db.ts).
 */
async function getCounts() {
  return {
    actors: await db.threatActor.count(),
    campaigns: await db.campaign.count({ where: { status: "ACTIVE" } }),
    indicators: await db.indicator.count({ where: { whitelisted: false } }),
    kev: await db.vulnerability.count({ where: { knownExploited: true } }),
    techniques: await db.technique.count({ where: { deprecated: false } }),
    reports: await db.report.count(),
    sources: await db.source.count({ where: { enabled: true } }),
    news: await db.newsItem.count(),
  };
}

const TILES = [
  { key: "actors", label: "Threat actors", icon: Users, href: "/actors" },
  { key: "campaigns", label: "Active campaigns", icon: Target, href: "/campaigns" },
  { key: "indicators", label: "Indicators", icon: Database, href: "/indicators" },
  { key: "kev", label: "Known exploited CVEs", icon: ShieldAlert, href: "/vulnerabilities?kev=true" },
  { key: "techniques", label: "ATT&CK techniques", icon: Radar, href: "/attack" },
  { key: "news", label: "News items", icon: Newspaper, href: "/news" },
  { key: "reports", label: "Reports", icon: FileText, href: "/reports" },
  { key: "sources", label: "Enabled feeds", icon: Rss, href: "/feeds" },
] as const;

export default async function DashboardPage() {
  const user = await requireUser();
  const counts = await getCounts();

  const recentNews = await db.newsItem.findMany({
    orderBy: [{ relevanceScore: "desc" }, { publishedAt: "desc" }],
    take: 6,
    include: { source: { select: { name: true } } },
  });

  const topKev = await db.vulnerability.findMany({
    where: { knownExploited: true },
    // `nulls: "last"` is essential: Postgres defaults to NULLS FIRST on DESC,
    // so unscored CVEs would sort above every scored one and the panel would
    // claim an EPSS ranking while showing unranked rows.
    orderBy: [
      { epssScore: { sort: "desc", nulls: "last" } },
      { cvssV3: { sort: "desc", nulls: "last" } },
    ],
    take: 6,
  });

  const staleFeeds = await db.source.findMany({
    where: { enabled: true, OR: [{ lastStatus: "error" }, { lastRunAt: null }] },
    select: { id: true, name: true, lastStatus: true, lastError: true },
    take: 5,
  });

  const empty = counts.actors === 0 && counts.indicators === 0;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">
          Welcome back, {user.name.split(" ")[0]}
        </h1>
        <p className="mt-1 text-sm text-ink-muted">
          Live platform overview. Feeds refresh hourly via the worker.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {TILES.map((tile) => {
          const Icon = tile.icon;
          return (
            <Link key={tile.key} href={tile.href}>
              <Card className="p-4 transition-colors hover:bg-surface-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-xs text-ink-muted">{tile.label}</p>
                    <p className="tabular mt-1.5 text-2xl font-semibold text-ink">
                      {counts[tile.key].toLocaleString()}
                    </p>
                  </div>
                  <span className="grid size-8 shrink-0 place-items-center rounded-md bg-surface-2 text-ink-faint">
                    <Icon className="size-4" />
                  </span>
                </div>
              </Card>
            </Link>
          );
        })}
      </div>

      {staleFeeds.length > 0 ? (
        <Card>
          <CardHeader
            title="Feeds needing attention"
            hint="A silently dead feed is worse than no feed"
          />
          <ul className="divide-y divide-line/60">
            {staleFeeds.map((f) => (
              <li key={f.id} className="flex items-center gap-3 px-4 py-2.5">
                <span className="text-sm text-ink">{f.name}</span>
                <span className="ml-auto truncate text-xs text-danger" title={f.lastError ?? ""}>
                  {f.lastStatus === "error" ? f.lastError?.slice(0, 60) : "never run"}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Highest-risk exploited CVEs"
            hint="CISA KEV, ranked by EPSS exploit probability"
          />
          {topKev.length === 0 ? (
            <EmptyState
              title="No vulnerability data"
              description="Run `npm run worker -- --run-now` to pull CISA KEV and EPSS."
            />
          ) : (
            <ul className="divide-y divide-line/60">
              {topKev.map((v) => (
                <li key={v.id}>
                  <Link
                    href={`/vulnerabilities/${v.cveId}`}
                    className="flex items-baseline gap-3 px-4 py-2.5 hover:bg-surface-2"
                  >
                    <span className="font-mono text-xs text-ink">{v.cveId}</span>
                    <span className="min-w-0 flex-1 truncate text-xs text-ink-muted">
                      {v.description ?? ""}
                    </span>
                    {v.epssScore != null ? (
                      <span className="tabular shrink-0 text-xs text-sev-critical">
                        {(v.epssScore * 100).toFixed(0)}%
                      </span>
                    ) : null}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title="Threat news" hint="Most relevant first" />
          {recentNews.length === 0 ? (
            <EmptyState
              title="No news yet"
              description="Run the worker to pull from the configured vendor and government feeds."
            />
          ) : (
            <ul className="divide-y divide-line/60">
              {recentNews.map((n) => (
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
                    {n.source?.name ?? "unknown"} ·{" "}
                    {n.publishedAt.toISOString().slice(0, 10)}
                    {n.linkedCveIds.length > 0
                      ? ` · ${n.linkedCveIds.length} CVE${n.linkedCveIds.length === 1 ? "" : "s"}`
                      : ""}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {empty ? (
        <Card>
          <EmptyState
            title="The platform is running, but empty"
            description="Run `npm run db:seed:demo` for sample actors, `npm run attack:sync` for ATT&CK, and `npm run worker -- --run-now` to pull live feeds."
          />
        </Card>
      ) : null}
    </div>
  );
}
