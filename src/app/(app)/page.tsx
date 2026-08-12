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
import { HorizontalBarChart, type BarDatum } from "@/components/ui/charts";
import { TrendArea, type TrendPoint } from "@/components/ui/trend-area";
import { getMatrix } from "@/lib/attack/matrix";

export const metadata = { title: "Dashboard · Pulse Intelligence" };

const TRENDDAYS = 30;

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

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "var(--color-sev-critical)",
  HIGH: "var(--color-sev-high)",
  MEDIUM: "var(--color-sev-medium)",
  LOW: "var(--color-sev-low)",
  INFO: "var(--color-sev-info)",
};

const CVSS_BAND_COLOR: Record<string, string> = {
  Critical: "var(--color-sev-critical)",
  High: "var(--color-sev-high)",
  Medium: "var(--color-sev-medium)",
  Low: "var(--color-sev-low)",
  Unscored: "var(--color-sev-info)",
};

/** Fills in zero-count days so the trend line doesn't skip gaps in the data. */
function fillDays(
  rows: { day: Date; count: bigint | number }[],
  days: number,
): TrendPoint[] {
  const counts = new Map(
    rows.map((r) => [r.day.toISOString().slice(0, 10), Number(r.count)]),
  );
  const points: TrendPoint[] = [];
  const start = new Date();
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - (days - 1));

  for (let i = 0; i < days; i++) {
    const d = new Date(start);
    d.setUTCDate(d.getUTCDate() + i);
    const key = d.toISOString().slice(0, 10);
    points.push({ date: key.slice(5), value: counts.get(key) ?? 0 });
  }
  return points;
}

export default async function DashboardPage() {
  const user = await requireUser();
  const trendSince = new Date();
  trendSince.setUTCDate(trendSince.getUTCDate() - TRENDDAYS);

  const [
    counts,
    recentNews,
    topKev,
    staleFeeds,
    newIndicatorsByDay,
    newCveByDay,
    severityGroups,
    typeGroups,
    cvssCounts,
    matrix,
  ] = await Promise.all([
    db.$queryRaw<
      [
        {
          actors: bigint;
          campaigns: bigint;
          indicators: bigint;
          kev: bigint;
          techniques: bigint;
          reports: bigint;
          sources: bigint;
          news: bigint;
        },
      ]
    >`
      SELECT 
        (SELECT count(*)::bigint FROM "ThreatActor") as actors,
        (SELECT count(*)::bigint FROM "Campaign" WHERE status = 'ACTIVE') as campaigns,
        (SELECT count(*)::bigint FROM "Indicator" WHERE whitelisted = false) as indicators,
        (SELECT count(*)::bigint FROM "Vulnerability" WHERE "knownExploited" = true) as kev,
        (SELECT count(*)::bigint FROM "Technique" WHERE deprecated = false) as techniques,
        (SELECT count(*)::bigint FROM "Report") as reports,
        (SELECT count(*)::bigint FROM "Source" WHERE enabled = true) as sources,
        (SELECT count(*)::bigint FROM "NewsItem") as news
    `.then((res) => ({
      actors: Number(res[0].actors),
      campaigns: Number(res[0].campaigns),
      indicators: Number(res[0].indicators),
      kev: Number(res[0].kev),
      techniques: Number(res[0].techniques),
      reports: Number(res[0].reports),
      sources: Number(res[0].sources),
      news: Number(res[0].news),
    })),
    db.newsItem.findMany({
      orderBy: [{ relevanceScore: "desc" }, { publishedAt: "desc" }],
      take: 6,
      include: { source: { select: { name: true } } },
    }),
    db.vulnerability.findMany({
      where: { knownExploited: true },
      orderBy: [
        { epssScore: { sort: "desc", nulls: "last" } },
        { cvssV3: { sort: "desc", nulls: "last" } },
      ],
      take: 6,
    }),
    db.source.findMany({
      where: { enabled: true, OR: [{ lastStatus: "error" }, { lastRunAt: null }] },
      select: { id: true, name: true, lastStatus: true, lastError: true },
      take: 5,
    }),
    db.$queryRaw<{ day: Date; count: bigint }[]>`
      SELECT date_trunc('day', "createdAt") AS day, count(*)::bigint AS count
      FROM "Indicator"
      WHERE "createdAt" >= ${trendSince}
      GROUP BY 1 ORDER BY 1
    `,
    db.$queryRaw<{ day: Date; count: bigint }[]>`
      SELECT date_trunc('day', "publishedAt") AS day, count(*)::bigint AS count
      FROM "Vulnerability"
      WHERE "publishedAt" >= ${trendSince}
      GROUP BY 1 ORDER BY 1
    `,
    db.indicator.groupBy({
      by: ["severity"],
      where: { whitelisted: false },
      _count: { _all: true },
    }),
    db.indicator.groupBy({
      by: ["type"],
      where: { whitelisted: false },
      _count: { _all: true },
    }),
    db.$queryRaw<
      [
        {
          critical: bigint;
          high: bigint;
          medium: bigint;
          low: bigint;
          unscored: bigint;
        },
      ]
    >`
      SELECT
        count(*) FILTER (WHERE "cvssV3" >= 9)::bigint as critical,
        count(*) FILTER (WHERE "cvssV3" >= 7 AND "cvssV3" < 9)::bigint as high,
        count(*) FILTER (WHERE "cvssV3" >= 4 AND "cvssV3" < 7)::bigint as medium,
        count(*) FILTER (WHERE "cvssV3" < 4)::bigint as low,
        count(*) FILTER (WHERE "cvssV3" IS NULL)::bigint as unscored
      FROM "Vulnerability"
    `.then((res) => ({
      critical: Number(res[0].critical),
      high: Number(res[0].high),
      medium: Number(res[0].medium),
      low: Number(res[0].low),
      unscored: Number(res[0].unscored),
    })),
    getMatrix("ENTERPRISE"),
  ]);

  const empty = counts.actors === 0 && counts.indicators === 0;

  const severityBars: BarDatum[] = (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const)
    .map((sev) => ({
      label: sev,
      value: severityGroups.find((g) => g.severity === sev)?._count._all ?? 0,
      color: SEVERITY_COLOR[sev],
      href: `/indicators?severity=${sev}`,
    }))
    .filter((b) => b.value > 0);

  const cvssBars: BarDatum[] = [
    { label: "Critical (9-10)", value: cvssCounts.critical, color: CVSS_BAND_COLOR.Critical },
    { label: "High (7-9)", value: cvssCounts.high, color: CVSS_BAND_COLOR.High },
    { label: "Medium (4-7)", value: cvssCounts.medium, color: CVSS_BAND_COLOR.Medium },
    { label: "Low (0-4)", value: cvssCounts.low, color: CVSS_BAND_COLOR.Low },
    { label: "Unscored", value: cvssCounts.unscored, color: CVSS_BAND_COLOR.Unscored },
  ].filter((b) => b.value > 0);

  const sortedTypes = [...typeGroups].sort((a, b) => b._count._all - a._count._all);
  const topTypes = sortedTypes.slice(0, 7);
  const otherTypesTotal = sortedTypes.slice(7).reduce((sum, t) => sum + t._count._all, 0);
  const typeBars: BarDatum[] = [
    ...topTypes.map((t) => ({
      label: t.type,
      value: t._count._all,
      href: `/indicators?type=${t.type}`,
    })),
    ...(otherTypesTotal > 0 ? [{ label: "Other", value: otherTypesTotal }] : []),
  ];

  const tacticBars: BarDatum[] = matrix.columns
    .filter((c) => c.techniques.length > 0)
    .map((c) => {
      const covered = c.techniques.filter((t) => t.actorCount > 0).length;
      return {
        label: c.name,
        value: Math.round((covered / c.techniques.length) * 100),
        color: "var(--color-chart-1)",
      };
    })
    .sort((a, b) => b.value - a.value);

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
            title="New indicators"
            hint={`Last ${TRENDDAYS} days, by day ingested`}
          />
          <TrendArea data={fillDays(newIndicatorsByDay, TRENDDAYS)} color="var(--color-chart-1)" />
        </Card>
        <Card>
          <CardHeader
            title="New CVEs published"
            hint={`Last ${TRENDDAYS} days, by NVD publish date`}
          />
          <TrendArea data={fillDays(newCveByDay, TRENDDAYS)} color="var(--color-chart-2)" />
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Indicator severity" hint="Non-whitelisted, current" />
          <HorizontalBarChart data={severityBars} />
        </Card>
        <Card>
          <CardHeader title="Indicator types" hint="Top 7, rest folded into Other" />
          <HorizontalBarChart data={typeBars} />
        </Card>
        <Card>
          <CardHeader title="Vulnerability severity" hint="By CVSS v3 band" />
          <HorizontalBarChart data={cvssBars} />
        </Card>
        <Card>
          <CardHeader
            title="ATT&CK coverage by tactic"
            hint={`${matrix.coveredTechniques} of ${matrix.totalTechniques} enterprise techniques mapped to a tracked actor`}
          />
          <HorizontalBarChart data={tacticBars} formatValue={(v) => `${v}%`} />
        </Card>
      </div>

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
