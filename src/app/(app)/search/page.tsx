import Link from "next/link";
import { redirect } from "next/navigation";
import { requireUser } from "@/lib/auth/dal";
import { exactIndicatorMatch, search, type SearchHitType } from "@/lib/search/query";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";
import { PageHeader } from "@/components/ui/page";

export const metadata = { title: "Search · Pulse Intelligence" };

const TYPE_LABELS: Record<SearchHitType, string> = {
  actor: "Threat actor",
  campaign: "Campaign",
  indicator: "Indicator",
  report: "Report",
  technique: "Technique",
  malware: "Malware",
  tool: "Tool",
  vulnerability: "Vulnerability",
};

const TYPE_TONE: Record<SearchHitType, string> = {
  actor: "text-brand",
  campaign: "text-accent",
  indicator: "text-sev-low",
  report: "text-ink-muted",
  technique: "text-sev-medium",
  malware: "text-sev-high",
  tool: "text-sev-info",
  vulnerability: "text-sev-critical",
};

export default async function SearchPage(props: {
  searchParams: Promise<{ q?: string }>;
}) {
  await requireUser();
  const { q } = await props.searchParams;
  const query = (q ?? "").trim();

  if (!query) {
    return (
      <div className="mx-auto max-w-4xl">
        <PageHeader title="Search" />
        <Card>
          <EmptyState
            title="Search everything"
            description="Actors, aliases, campaigns, indicators, reports, techniques, malware and CVEs. Paste an IOC to jump straight to it."
          />
        </Card>
      </div>
    );
  }

  // Pasting a hash or domain should land on the record, not a results list.
  const exact = await exactIndicatorMatch(query);
  if (exact) redirect(`/indicators/${exact.id}`);

  const hits = await search(query);

  // Preserve the entity ordering rather than interleaving purely by score —
  // grouped results are far easier to scan.
  const grouped = new Map<SearchHitType, typeof hits>();
  for (const hit of hits) {
    const list = grouped.get(hit.type) ?? [];
    list.push(hit);
    grouped.set(hit.type, list);
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title={`Results for “${query}”`}
        description={`${hits.length} match${hits.length === 1 ? "" : "es"}`}
      />

      {hits.length === 0 ? (
        <Card>
          <EmptyState
            title="No matches"
            description="Try a shorter query, an alias, or part of an indicator value. Full-text search covers names, descriptions and report bodies."
          />
        </Card>
      ) : (
        <div className="space-y-4">
          {[...grouped.entries()].map(([type, list]) => (
            <Card key={type}>
              <CardHeader title={TYPE_LABELS[type]} hint={`${list.length}`} />
              <ul className="divide-y divide-line/60">
                {list.map((hit) => (
                  <li key={`${hit.type}-${hit.id}`}>
                    <Link
                      href={hit.href}
                      className="flex items-baseline gap-3 px-4 py-2.5 hover:bg-surface-2"
                    >
                      <span className={`text-sm ${TYPE_TONE[type]}`}>●</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-ink">
                          {hit.title}
                        </span>
                        {hit.subtitle ? (
                          <span className="block truncate text-xs text-ink-faint">
                            {hit.subtitle}
                          </span>
                        ) : null}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
