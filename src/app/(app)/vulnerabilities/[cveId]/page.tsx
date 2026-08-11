import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink, ShieldAlert } from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";
import { DetailRow, Muted, PageHeader } from "@/components/ui/page";
import { CveReportActions } from "./report-actions";
import { computePriority, PRIORITY_COLORS } from "@/lib/vuln/priority";

export async function generateMetadata(props: {
  params: Promise<{ cveId: string }>;
}) {
  const { cveId } = await props.params;
  return { title: `${decodeURIComponent(cveId).toUpperCase()} · Pulse Intelligence` };
}

/** A labeled 0-max meter — same visual language as ConfidenceBar, just bigger,
 *  for the two headline numbers an analyst scans first. */
function Meter({
  label,
  value,
  max,
  display,
  tone,
  color,
}: {
  label: string;
  value: number | null;
  max: number;
  display: string;
  tone: string;
  color: string;
}) {
  const pct = value != null ? Math.max(2, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between">
        <span className="text-xs text-ink-muted">{label}</span>
        <span className={`tabular text-sm font-semibold ${value != null ? tone : "text-ink-faint"}`}>
          {display}
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-surface-3">
        {value != null ? (
          <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
        ) : null}
      </div>
    </div>
  );
}

function cvssTone(score: number | null): string {
  if (score === null) return "text-ink-faint";
  if (score >= 9) return "text-sev-critical";
  if (score >= 7) return "text-sev-high";
  if (score >= 4) return "text-sev-medium";
  return "text-sev-low";
}

function cvssColor(score: number | null): string {
  if (score === null) return "#6b7280";
  if (score >= 9) return "var(--color-sev-critical)";
  if (score >= 7) return "var(--color-sev-high)";
  if (score >= 4) return "var(--color-sev-medium)";
  return "var(--color-sev-low)";
}

function epssTone(score: number | null): string {
  if (score === null) return "text-ink-faint";
  const pct = score * 100;
  if (pct >= 50) return "text-sev-critical";
  if (pct >= 10) return "text-sev-high";
  if (pct >= 1) return "text-sev-medium";
  return "text-sev-low";
}

function epssColor(score: number | null): string {
  if (score === null) return "#6b7280";
  const pct = score * 100;
  if (pct >= 50) return "var(--color-sev-critical)";
  if (pct >= 10) return "var(--color-sev-high)";
  if (pct >= 1) return "var(--color-sev-medium)";
  return "var(--color-sev-low)";
}

export default async function VulnerabilityPage(props: {
  params: Promise<{ cveId: string }>;
}) {
  await requireUser();
  const { cveId: raw } = await props.params;
  const cveId = decodeURIComponent(raw).toUpperCase();

  const vuln = await db.vulnerability.findUnique({ where: { cveId } });
  if (!vuln) notFound();

  // News that mentions this CVE — the pivot from "a CVE exists" to "people are
  // writing about it", which is usually what makes it urgent.
  const news = await db.newsItem.findMany({
    where: { linkedCveIds: { has: cveId } },
    orderBy: { publishedAt: "desc" },
    take: 10,
    include: { source: { select: { name: true } } },
  });

  // A CVE is also stored as a CVE-type Indicator when it's been ingested via a
  // feed/report — that's where attribution (which actor/campaign this maps to)
  // and analyst-report mentions actually live, same join tables every other
  // entity in the platform uses (design rule 1: confidence + addedById).
  const indicator = await db.indicator.findUnique({
    where: { type_normalizedValue: { type: "CVE", normalizedValue: cveId } },
    include: {
      actors: { include: { actor: true }, orderBy: { confidence: "desc" } },
      campaigns: { include: { campaign: true }, orderBy: { confidence: "desc" } },
      reports: { include: { report: true }, orderBy: { confidence: "desc" } },
    },
  });

  const priority = computePriority(
    vuln.cvssV3 ?? vuln.cvssV4,
    vuln.epssScore,
    vuln.knownExploited,
  );
  const priorityColors = PRIORITY_COLORS[priority.tier];

  const reportData = {
    cveId,
    description: vuln.description,
    cvssV3: vuln.cvssV3,
    cvssV4: vuln.cvssV4,
    epssScore: vuln.epssScore,
    knownExploited: vuln.knownExploited,
    kevDateAdded: vuln.kevDateAdded?.toISOString().slice(0, 10) ?? null,
    publishedAt: vuln.publishedAt?.toISOString().slice(0, 10) ?? null,
    vendorRefs: vuln.vendorRefs,
    actors: indicator?.actors.map((a) => ({ name: a.actor.name, confidence: a.confidence })) ?? [],
    campaigns:
      indicator?.campaigns.map((c) => ({ name: c.campaign.name, status: c.campaign.status })) ?? [],
    reports: indicator?.reports.map((r) => ({ title: r.report.title, id: r.report.id })) ?? [],
    news: news.map((n) => ({
      title: n.title,
      source: n.source?.name ?? "unknown",
      date: n.publishedAt.toISOString().slice(0, 10),
    })),
  };

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title={cveId}
        action={
          <div className="flex items-center gap-2">
            <CveReportActions data={reportData} />
            <a
              href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
            >
              NVD
              <ExternalLink className="size-3.5" />
            </a>
          </div>
        }
      />

      {vuln.knownExploited ? (
        <div className="mb-4 flex items-start gap-2 rounded-[--radius-card] border border-sev-critical/40 bg-sev-critical/10 px-4 py-3 text-sm text-sev-critical">
          <ShieldAlert className="mt-0.5 size-4 shrink-0" />
          <div>
            <p className="font-medium">
              On the CISA Known Exploited Vulnerabilities catalogue.
            </p>
            <p className="mt-0.5 text-xs opacity-90">
              Confirmed exploitation in the wild
              {vuln.kevDateAdded
                ? `, added ${vuln.kevDateAdded.toISOString().slice(0, 10)}`
                : ""}
              . Patch this ahead of higher-CVSS items that are not being exploited.
            </p>
          </div>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Description" />
            <div className="whitespace-pre-wrap px-4 py-4 text-sm leading-relaxed text-ink">
              {vuln.description ?? "No description available."}
            </div>
          </Card>

          {reportData.actors.length > 0 || reportData.campaigns.length > 0 ? (
            <Card>
              <CardHeader title="Attribution" hint="Who this CVE has been linked to, and how confidently" />
              <ul className="divide-y divide-line/60">
                {reportData.actors.map((a) => (
                  <li key={a.name} className="flex items-center justify-between px-4 py-2.5 text-sm">
                    <span className="text-ink-faint">Actor</span>
                    <span className="text-ink">{a.name}</span>
                    <span className="tabular text-xs text-ink-muted">{a.confidence}%</span>
                  </li>
                ))}
                {reportData.campaigns.map((c) => (
                  <li key={c.name} className="flex items-center justify-between px-4 py-2.5 text-sm">
                    <span className="text-ink-faint">Campaign</span>
                    <span className="text-ink">{c.name}</span>
                    <span className="text-xs text-ink-muted">{c.status}</span>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}

          {reportData.reports.length > 0 ? (
            <Card>
              <CardHeader title="Related analyst reports" />
              <ul className="divide-y divide-line/60">
                {reportData.reports.map((r) => (
                  <li key={r.id} className="px-4 py-2.5">
                    <Link href={`/reports/${r.id}`} className="text-sm text-ink hover:text-brand">
                      {r.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}

          <Card>
            <CardHeader title="Media coverage" hint={`${news.length} articles mention this CVE`} />
            {news.length === 0 ? (
              <EmptyState
                title="No coverage yet"
                description="News items mentioning this CVE will appear here as feeds run."
              />
            ) : (
              <ul className="divide-y divide-line/60">
                {news.map((n) => (
                  <li key={n.id} className="px-4 py-2.5">
                    <a
                      href={n.url}
                      target="_blank"
                      rel="noopener noreferrer nofollow"
                      className="block text-sm text-ink hover:text-brand"
                    >
                      {n.title}
                    </a>
                    <p className="mt-0.5 text-[11px] text-ink-faint">
                      {n.source?.name ?? "unknown"} ·{" "}
                      {n.publishedAt.toISOString().slice(0, 10)}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <div className="lg:col-span-1">
          <Card>
            <CardHeader title="Scoring" />
            {/* Priority score — the first number a VM team should look at */}
            <div className="border-b border-line px-4 py-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[11px] text-ink-muted">Priority score</p>
                  <p className="text-[11px] text-ink-faint mt-0.5">{priority.reasoning}</p>
                </div>
                <span
                  className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-bold ${priorityColors.bg} ${priorityColors.text} ${priorityColors.border}`}
                >
                  <span className="tabular text-lg">{priority.score}</span>
                  <span className="text-xs font-medium opacity-80">{priority.label}</span>
                </span>
              </div>
            </div>
            <div className="space-y-4 px-4 py-4">
              <Meter
                label="CVSS v3"
                value={vuln.cvssV3}
                max={10}
                display={vuln.cvssV3 != null ? vuln.cvssV3.toFixed(1) : "Not scored"}
                tone={cvssTone(vuln.cvssV3)}
                color={cvssColor(vuln.cvssV3)}
              />
              <Meter
                label="EPSS — 30-day exploit probability"
                value={vuln.epssScore}
                max={1}
                display={vuln.epssScore != null ? `${(vuln.epssScore * 100).toFixed(2)}%` : "Not scored"}
                tone={epssTone(vuln.epssScore)}
                color={epssColor(vuln.epssScore)}
              />
            </div>

            <dl>
              <DetailRow label="CVSS v4">
                {vuln.cvssV4 != null ? (
                  <span className="tabular">{vuln.cvssV4.toFixed(1)}</span>
                ) : (
                  <Muted>Not scored</Muted>
                )}
              </DetailRow>
              <DetailRow label="Exploited">
                {vuln.knownExploited ? (
                  <span className="text-sev-critical">Yes — CISA KEV</span>
                ) : (
                  <Muted>Not known</Muted>
                )}
              </DetailRow>
              <DetailRow label="Published">
                {vuln.publishedAt?.toISOString().slice(0, 10) ?? <Muted>Unknown</Muted>}
              </DetailRow>
            </dl>
          </Card>

          {vuln.vendorRefs.length > 0 ? (
            <Card className="mt-4">
              <CardHeader title="References" />
              <ul className="divide-y divide-line/60">
                {vuln.vendorRefs.slice(0, 8).map((ref) => (
                  <li key={ref} className="px-4 py-2">
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer nofollow"
                      className="block break-all text-xs text-brand hover:underline"
                    >
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}
        </div>
      </div>

      <p className="mt-4 text-xs text-ink-faint">
        <Link href="/vulnerabilities" className="hover:text-ink">
          ← All vulnerabilities
        </Link>
      </p>
    </div>
  );
}
