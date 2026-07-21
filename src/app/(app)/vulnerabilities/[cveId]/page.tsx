import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink, ShieldAlert } from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";
import { DetailRow, Muted, PageHeader } from "@/components/ui/page";

export async function generateMetadata(props: {
  params: Promise<{ cveId: string }>;
}) {
  const { cveId } = await props.params;
  return { title: `${decodeURIComponent(cveId).toUpperCase()} · Pulse Intelligence` };
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

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title={cveId}
        action={
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
          >
            NVD
            <ExternalLink className="size-3.5" />
          </a>
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

          <Card>
            <CardHeader title="Coverage" hint={`${news.length} articles mention this CVE`} />
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
            <dl>
              <DetailRow label="CVSS v3">
                {vuln.cvssV3 != null ? (
                  <span className="tabular">{vuln.cvssV3.toFixed(1)}</span>
                ) : (
                  <Muted>Not scored</Muted>
                )}
              </DetailRow>
              <DetailRow label="CVSS v4">
                {vuln.cvssV4 != null ? (
                  <span className="tabular">{vuln.cvssV4.toFixed(1)}</span>
                ) : (
                  <Muted>Not scored</Muted>
                )}
              </DetailRow>
              <DetailRow label="EPSS">
                {vuln.epssScore != null ? (
                  <span className="tabular">
                    {(vuln.epssScore * 100).toFixed(2)}%
                    <span className="ml-1 text-xs text-ink-faint">
                      chance of exploitation in 30 days
                    </span>
                  </span>
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
