import "server-only";

import { db } from "@/lib/db";
import { detectType, normalize } from "@/lib/ioc/normalize";

/**
 * Global search.
 *
 * Runs one targeted query per entity type in parallel and merges, rather than a
 * single UNION. Each query then uses its own index cleanly, and adding an entity
 * type later is a local change instead of surgery on a 200-line statement.
 *
 * The tsvector expressions below must stay byte-identical to the ones in
 * prisma/migrations/20260721010000_search_indexes/migration.sql, or Postgres
 * will silently fall back to a sequential scan.
 */

export type SearchHitType =
  | "actor"
  | "campaign"
  | "indicator"
  | "report"
  | "technique"
  | "malware"
  | "tool"
  | "vulnerability";

export type SearchHit = {
  type: SearchHitType;
  id: string;
  title: string;
  subtitle: string | null;
  href: string;
  rank: number;
};

const PER_TYPE_LIMIT = 5;

type Row = { id: string; title: string; subtitle: string | null; rank: number };

/**
 * `websearch_to_tsquery` is used rather than `to_tsquery` because it never
 * throws on user input — unbalanced quotes and stray operators are tolerated
 * instead of turning a search box into a 500.
 */
export async function search(rawQuery: string): Promise<SearchHit[]> {
  const q = rawQuery.trim();
  if (q.length < 2) return [];

  const like = `%${q}%`;

  const [actors, campaigns, indicators, reports, techniques, malware, tools, vulns] =
    await Promise.all([
      db.$queryRaw<Row[]>`
        SELECT "id", "name" AS title, "country" AS subtitle,
               ts_rank(
                 setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
                 setweight(to_tsvector('english', coalesce("description", '')), 'B'),
                 websearch_to_tsquery('english', ${q})
               ) + similarity("name", ${q}) AS rank
        FROM "ThreatActor"
        WHERE (
          setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
          setweight(to_tsvector('english', coalesce("description", '')), 'B')
        ) @@ websearch_to_tsquery('english', ${q})
           OR "name" ILIKE ${like}
           OR "id" IN (SELECT "actorId" FROM "ActorAlias" WHERE "alias" ILIKE ${like})
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,

      db.$queryRaw<Row[]>`
        SELECT "id", "name" AS title, "status"::text AS subtitle,
               ts_rank(
                 setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
                 setweight(to_tsvector('english', coalesce("description", '')), 'B'),
                 websearch_to_tsquery('english', ${q})
               ) + similarity("name", ${q}) AS rank
        FROM "Campaign"
        WHERE (
          setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
          setweight(to_tsvector('english', coalesce("description", '')), 'B')
        ) @@ websearch_to_tsquery('english', ${q})
           OR "name" ILIKE ${like}
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,

      // Indicators are matched by substring only — full-text stemming is
      // meaningless for hashes and hostnames.
      db.$queryRaw<Row[]>`
        SELECT "id", "value" AS title, "type"::text AS subtitle,
               similarity("normalizedValue", ${q}) AS rank
        FROM "Indicator"
        WHERE "normalizedValue" ILIKE ${like}
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,

      db.$queryRaw<Row[]>`
        SELECT "id", "title", "summary" AS subtitle,
               ts_rank(
                 setweight(to_tsvector('english', coalesce("title", '')), 'A') ||
                 setweight(to_tsvector('english', coalesce("summary", '')), 'B') ||
                 setweight(to_tsvector('english', coalesce("body", '')), 'C'),
                 websearch_to_tsquery('english', ${q})
               ) AS rank
        FROM "Report"
        WHERE (
          setweight(to_tsvector('english', coalesce("title", '')), 'A') ||
          setweight(to_tsvector('english', coalesce("summary", '')), 'B') ||
          setweight(to_tsvector('english', coalesce("body", '')), 'C')
        ) @@ websearch_to_tsquery('english', ${q})
           OR "title" ILIKE ${like}
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,

      // attackId is matched exactly so "T1566" jumps straight to the technique.
      db.$queryRaw<Row[]>`
        SELECT "id", "name" AS title, "attackId" AS subtitle,
               CASE WHEN upper("attackId") = upper(${q}) THEN 10.0
                    ELSE similarity("name", ${q}) END AS rank
        FROM "Technique"
        WHERE "deprecated" = false AND (
          "attackId" ILIKE ${like}
          OR "name" ILIKE ${like}
          OR (
            setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
            setweight(to_tsvector('english', coalesce("description", '')), 'B')
          ) @@ websearch_to_tsquery('english', ${q})
        )
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,

      db.$queryRaw<Row[]>`
        SELECT "id", "name" AS title, "family" AS subtitle,
               similarity("name", ${q}) AS rank
        FROM "Malware"
        WHERE "name" ILIKE ${like} OR ${q} ILIKE ANY("aliases")
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,

      db.$queryRaw<Row[]>`
        SELECT "id", "name" AS title, NULL AS subtitle,
               similarity("name", ${q}) AS rank
        FROM "Tool"
        WHERE "name" ILIKE ${like} OR ${q} ILIKE ANY("aliases")
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,

      db.$queryRaw<Row[]>`
        SELECT "id", "cveId" AS title, left(coalesce("description", ''), 120) AS subtitle,
               CASE WHEN upper("cveId") = upper(${q}) THEN 10.0
                    ELSE similarity("cveId", ${q}) END AS rank
        FROM "Vulnerability"
        WHERE "cveId" ILIKE ${like}
        ORDER BY rank DESC
        LIMIT ${PER_TYPE_LIMIT}`,
    ]);

  const map = (rows: Row[], type: SearchHitType, path: string): SearchHit[] =>
    rows.map((r) => ({
      type,
      id: r.id,
      title: r.title,
      subtitle: r.subtitle,
      href: `${path}/${r.id}`,
      rank: Number(r.rank) || 0,
    }));

  return [
    ...map(actors, "actor", "/actors"),
    ...map(campaigns, "campaign", "/campaigns"),
    ...map(indicators, "indicator", "/indicators"),
    ...map(reports, "report", "/reports"),
    ...map(techniques, "technique", "/attack"),
    // Malware and tools share the `/malware/:id` detail route — a tool hit
    // resolves via the same table lookup the page itself does.
    ...map(malware, "malware", "/malware"),
    ...map(tools, "tool", "/malware"),
    ...map(vulns, "vulnerability", "/vulnerabilities"),
  ].sort((a, b) => b.rank - a.rank);
}

/**
 * If the query is itself an IOC, look for that exact indicator. Pasting a hash
 * into the search box should land on the indicator, not on a fuzzy text match.
 */
export async function exactIndicatorMatch(rawQuery: string) {
  const type = detectType(rawQuery);
  if (!type) return null;
  return db.indicator.findUnique({
    where: {
      type_normalizedValue: { type, normalizedValue: normalize(rawQuery, type) },
    },
  });
}
