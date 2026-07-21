import Link from "next/link";
import { ShieldAlert } from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { Pagination, Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, PageHeader } from "@/components/ui/page";

export const metadata = { title: "Vulnerabilities · Pulse Intelligence" };

const PAGE_SIZE = 50;

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
      // EPSS first: "how likely is this to be exploited" beats "how bad would it
      // be" for prioritisation. CVSS is the tiebreaker.
      //
      // `nulls: "last"` is essential — Postgres defaults to NULLS FIRST on DESC,
      // which would float every unscored CVE above the scored ones and invert
      // the entire point of the ordering.
      orderBy: [
        { epssScore: { sort: "desc", nulls: "last" } },
        { cvssV3: { sort: "desc", nulls: "last" } },
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
                  <Th className="text-right">CVSS</Th>
                  <Th className="text-right">EPSS</Th>
                  <Th>Status</Th>
                  <Th>Published</Th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((v) => (
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
                    <Td className={`tabular text-right text-xs ${cvssTone(v.cvssV3)}`}>
                      {v.cvssV3?.toFixed(1) ?? v.cvssV4?.toFixed(1) ?? "—"}
                    </Td>
                    <Td className="tabular text-right text-xs text-ink-muted">
                      {/* EPSS is a probability; percent is how analysts read it. */}
                      {v.epssScore != null
                        ? `${(v.epssScore * 100).toFixed(1)}%`
                        : "—"}
                    </Td>
                    <Td>
                      {v.knownExploited ? (
                        <span className="rounded border border-sev-critical/40 bg-sev-critical/10 px-1.5 py-0.5 text-[11px] text-sev-critical">
                          exploited
                        </span>
                      ) : (
                        <Muted>—</Muted>
                      )}
                    </Td>
                    <Td className="tabular text-xs text-ink-muted">
                      {v.publishedAt?.toISOString().slice(0, 10) ??
                        v.kevDateAdded?.toISOString().slice(0, 10) ?? <Muted>—</Muted>}
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
              basePath="/vulnerabilities"
            />
          </>
        )}
      </Card>
    </div>
  );
}
