import Link from "next/link";
import { Upload } from "lucide-react";
import { db } from "@/lib/db";
import { getCurrentUser, hasRole } from "@/lib/auth/dal";
import {
  Card,
  ConfidenceBar,
  EmptyState,
  SeverityBadge,
  TlpBadge,
} from "@/components/ui/primitives";
import { Pagination, Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, PageHeader, Tag } from "@/components/ui/page";
import { activeIndicatorWhere } from "@/lib/ioc/decay";
import { FreshnessBar } from "@/components/ui/freshness";
import { IndicatorFilters } from "./filters";
import { ExportMenu } from "./export-menu";

export const metadata = { title: "Indicators · Pulse Intelligence" };

const PAGE_SIZE = 50;

type SearchParams = {
  q?: string;
  type?: string;
  severity?: string;
  whitelisted?: string;
  page?: string;
};

export default async function IndicatorsPage(props: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await props.searchParams;
  const user = await getCurrentUser();
  const page = Math.max(1, Number(params.page) || 1);
  const now = new Date();

  const where = {
    ...(params.q
      ? { normalizedValue: { contains: params.q.toLowerCase() } }
      : {}),
    ...(params.type ? { type: params.type as never } : {}),
    ...(params.severity ? { severity: params.severity as never } : {}),
    // Whitelisted IOCs are hidden by default — they are noise in the working
    // view, but must stay findable to explain why something was not exported.
    whitelisted: params.whitelisted === "true",
    ...activeIndicatorWhere(now),
  };

  const [indicators, total, whitelistedCount] = await Promise.all([
    db.indicator.findMany({
      where,
      orderBy: { lastSeen: "desc" },
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: {
        source: { select: { name: true } },
        _count: { select: { enrichments: true, actors: true } },
      },
    }),
    db.indicator.count({ where }),
    db.indicator.count({ where: { whitelisted: true } }),
  ]);

  const filtered = Boolean(params.q || params.type || params.severity);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Indicators"
        description="Observables under management. Deduplicated on ingest."
        action={
          <div className="flex shrink-0 items-center gap-2">
            <ExportMenu />
            {user && hasRole(user, "ANALYST") ? (
              <Link
                href="/indicators/import"
                className="inline-flex items-center gap-1.5 rounded-md bg-brand px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover"
              >
                <Upload className="size-4" />
                Bulk import
              </Link>
            ) : null}
          </div>
        }
      />

      <Card>
        <IndicatorFilters whitelistedCount={whitelistedCount} />

        {indicators.length === 0 ? (
          <EmptyState
            title={
              filtered ? "No indicators match those filters" : "No indicators yet"
            }
            description={
              filtered
                ? "Try widening the search, or clear the filters."
                : "Paste IOCs via Bulk import, or connect a feed in Phase 5 to fill this automatically."
            }
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Type</Th>
                  <Th>Value</Th>
                  <Th>Severity</Th>
                  <Th>Confidence</Th>
                  <Th>Source</Th>
                  <Th>Tags</Th>
                  <Th>Last seen</Th>
                  <Th title="How much lifetime remains before this indicator expires from the working set">Freshness</Th>
                  <Th>TLP</Th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((i) => (
                  <Tr key={i.id} href={`/indicators/${i.id}`}>
                    <Td>
                      <span className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] uppercase text-ink-muted">
                        {i.type}
                      </span>
                    </Td>
                    <Td className="max-w-md">
                      <Link
                        href={`/indicators/${i.id}`}
                        className="block truncate font-mono text-xs text-ink hover:text-brand"
                        title={i.value}
                      >
                        {i.value}
                      </Link>
                    </Td>
                    <Td>
                      <SeverityBadge severity={i.severity} />
                    </Td>
                    <Td>
                      <ConfidenceBar value={i.confidence} />
                    </Td>
                    <Td className="text-xs text-ink-muted">
                      {i.source?.name ?? <Muted>manual</Muted>}
                    </Td>
                    <Td>
                      {i.tags.length ? (
                        <div className="flex flex-wrap gap-1">
                          {i.tags.slice(0, 2).map((t) => (
                            <Tag key={t}>{t}</Tag>
                          ))}
                        </div>
                      ) : (
                        <Muted>—</Muted>
                      )}
                    </Td>
                    <Td className="tabular text-xs text-ink-muted">
                      {i.lastSeen.toISOString().slice(0, 10)}
                    </Td>
                    <Td>
                      <FreshnessBar
                        firstSeen={i.firstSeen}
                        lastSeen={i.lastSeen}
                        expiresAt={i.expiresAt}
                        showDate
                      />
                    </Td>
                    <Td>
                      <TlpBadge tlp={i.tlp} />
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
              basePath="/indicators"
            />
          </>
        )}
      </Card>
    </div>
  );
}
