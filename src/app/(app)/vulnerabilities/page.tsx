import { Fragment } from "react";
import Link from "next/link";
import { ShieldAlert } from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { Pagination, Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, PageHeader } from "@/components/ui/page";
import { extractProduct } from "@/lib/vuln/product";
import { VulnGroupToggle } from "./vuln-group-toggle";
import { computePriority, PRIORITY_COLORS } from "@/lib/vuln/priority";

export const metadata = { title: "Vulnerabilities · Pulse Intelligence" };

const PAGE_SIZE = 50;

type Vuln = Awaited<ReturnType<typeof db.vulnerability.findMany>>[number];

/// Clubs consecutive same-product CVEs (already adjacent because they share
/// similar EPSS/CVSS/date, the current sort keys) behind a single collapsed
/// row, so e.g. a run of a dozen "Linux Kernel" entries doesn't dominate the
/// page. KEV rows are never folded in — an actively-exploited CVE must stay
/// visible on its own, regardless of what else shares its product.
function groupVulns(vulns: Vuln[]): Vuln[][] {
  const groups: Vuln[][] = [];
  let current: Vuln[] = [];
  let currentProduct: string | null = null;

  for (const v of vulns) {
    const product = v.knownExploited ? null : extractProduct(v.description);
    if (product && product === currentProduct) {
      current.push(v);
    } else {
      if (current.length) groups.push(current);
      current = [v];
      currentProduct = product;
    }
  }
  if (current.length) groups.push(current);

  // Groups of 1-2 aren't worth collapsing — only fold runs of 3+.
  return groups.flatMap((g) => (g.length >= 3 ? [g] : g.map((v) => [v])));
}

/** CVSS bands follow the standard qualitative severity ratings. */
function cvssTone(score: number | null): string {
  if (score === null) return "text-ink-faint";
  if (score >= 9) return "text-sev-critical";
  if (score >= 7) return "text-sev-high";
  if (score >= 4) return "text-sev-medium";
  return "text-sev-low";
}

export default async function VulnerabilitiesPage(props: {
  searchParams: Promise<{ page?: string; kev?: string; q?: string }>;
}) {
  await requireUser();
  const params = await props.searchParams;
  const page = Math.max(1, Number(params.page) || 1);
  const kevOnly = params.kev === "true";

  const where = {
    ...(kevOnly ? { knownExploited: true } : {}),
    ...(params.q
      ? { cveId: { contains: params.q.toUpperCase(), mode: "insensitive" as const } }
      : {}),
  };

  const [vulns, total, kevCount] = await Promise.all([
    db.vulnerability.findMany({
      where,
      // Most important first: CISA KEV (actively exploited) outranks
      // everything, then exploit probability (EPSS), then severity (CVSS),
      // then recency. A 90-day retention window (HANDOVER.md §4.6) already
      // keeps this list current, so leading with "what matters most" reads
      // better than "what's newest" once genuinely current data is assumed.
      //
      // `nulls: "last"` is essential — Postgres defaults to NULLS FIRST on DESC,
      // which would float every undated row above the dated ones.
      orderBy: [
        { knownExploited: "desc" },
        { epssScore: { sort: "desc", nulls: "last" } },
        { cvssV3: { sort: "desc", nulls: "last" } },
        { publishedAt: { sort: "desc", nulls: "last" } },
        { cveId: "desc" },
      ],
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
    }),
    db.vulnerability.count({ where }),
    db.vulnerability.count({ where: { knownExploited: true } }),
  ]);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Vulnerabilities"
        description="CVEs enriched with CISA KEV exploitation status and FIRST EPSS exploit probability."
      />

      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
          <form action="/vulnerabilities" method="get" className="min-w-48 flex-1">
            <input
              name="q"
              type="search"
              defaultValue={params.q ?? ""}
              placeholder="CVE-2024-3400…"
              className="w-full rounded-md border border-line bg-base px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none"
            />
            {kevOnly ? <input type="hidden" name="kev" value="true" /> : null}
          </form>

          <Link
            href={kevOnly ? "/vulnerabilities" : "/vulnerabilities?kev=true"}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm transition-colors ${
              kevOnly
                ? "bg-sev-critical/15 text-sev-critical"
                : "border border-line text-ink-muted hover:bg-surface-2 hover:text-ink"
            }`}
          >
            <ShieldAlert className="size-4" />
            Known exploited
            <span className="tabular text-xs opacity-80">({kevCount})</span>
          </Link>
        </div>

        {vulns.length === 0 ? (
          <EmptyState
            title="No vulnerabilities yet"
            description="Run the worker (`npm run worker -- --run-now`) to pull CISA KEV, NVD and EPSS."
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>CVE</Th>
                  <Th>Description</Th>
                  <Th title="Composite priority: KEV + EPSS + CVSS">Priority</Th>
                  <Th className="text-right">CVSS</Th>
                  <Th className="text-right">EPSS</Th>
                  <Th>Published</Th>
                </tr>
              </thead>
              <tbody>
                {groupVulns(vulns).map((group) => {
                  const [lead, ...rest] = group;
                  const product = extractProduct(lead.description);
                  const row = (v: (typeof vulns)[number]) => {
                    const priority = computePriority(v.cvssV3 ?? v.cvssV4, v.epssScore, v.knownExploited);
                    const colors = PRIORITY_COLORS[priority.tier];
                    return (
                    <Tr key={v.id}>
                      <Td>
                        <Link
                          href={`/vulnerabilities/${v.cveId}`}
                          className="font-mono text-xs text-ink hover:text-brand"
                        >
                          {v.cveId}
                        </Link>
                      </Td>
                      <Td className="max-w-lg">
                        <span className="block truncate text-xs text-ink-muted">
                          {v.description ?? <Muted>—</Muted>}
                        </span>
                      </Td>
                      <Td>
                        <span
                          className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-semibold ${colors.bg} ${colors.text} ${colors.border}`}
                          title={priority.reasoning}
                        >
                          <span className="tabular font-bold">{priority.score}</span>
                          {priority.label}
                        </span>
                      </Td>
                      <Td className={`tabular text-right text-xs ${cvssTone(v.cvssV3)}`}>
                        {v.cvssV3?.toFixed(1) ?? v.cvssV4?.toFixed(1) ?? "—"}
                      </Td>
                      <Td className="tabular text-right text-xs text-ink-muted">
                        {v.epssScore != null
                          ? `${(v.epssScore * 100).toFixed(1)}%`
                          : "—"}
                      </Td>
                      <Td className="tabular text-xs text-ink-muted">
                        {v.publishedAt?.toISOString().slice(0, 10) ??
                          v.kevDateAdded?.toISOString().slice(0, 10) ?? <Muted>—</Muted>}
                      </Td>
                    </Tr>
                  );};

                  if (rest.length === 0) return row(lead);

                  return (
                    <Fragment key={lead.id}>
                      {row(lead)}
                      <VulnGroupToggle label={product ?? "similar"} count={rest.length}>
                        {rest.map(row)}
                      </VulnGroupToggle>
                    </Fragment>
                  );
                })}
              </tbody>
            </Table>
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              total={total}
              searchParams={params}
              basePath="/vulnerabilities"
            />
          </>
        )}
      </Card>
    </div>
  );
}
