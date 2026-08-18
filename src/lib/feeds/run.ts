import { gunzipSync } from "node:zlib";
import { db } from "@/lib/db";
import { findCatalogSource, type FeedHandler } from "@/lib/feeds/catalog";
import {
  parseCsv,
  parseEpss,
  parseKev,
  parseNvd,
  parseRss,
  type ParsedVulnerability,
} from "@/lib/feeds/parsers";
import { ingestParsed, ingestText } from "@/lib/ioc/ingest";
import { parseIndicator } from "@/lib/ioc/normalize";
import { getSecret } from "@/lib/enrichment/secrets";

/**
 * Feed execution.
 *
 * Every run updates the source's health counters whether it succeeded or not.
 * A feed that silently stops returning data is worse than no feed at all, so
 * "when did this last work" is first-class state, not a log line.
 */

export type FeedRunResult = {
  sourceId: string;
  sourceName: string;
  ok: boolean;
  itemsIngested: number;
  itemsDuped: number;
  message: string;
};

const USER_AGENT =
  "PulseIntelligence/0.1 (self-hosted threat intelligence platform)";

/**
 * NVD API 2.0 accepts a bare `apiKey` header. Without one, requests are capped
 * at 5/rolling-30s and NIST's service intermittently 403s keyless traffic —
 * with one, 50/rolling-30s. Optional: the feed still runs without a key, just
 * closer to the edge of getting throttled.
 */
function nvdHeaders(): Record<string, string> {
  const key = getSecret("nvd");
  return key ? { apiKey: key } : {};
}

async function fetchFeed(url: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60_000);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: { "User-Agent": USER_AGENT, ...(init.headers ?? {}) },
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Upsert vulnerabilities without clobbering fields another feed owns.
 *
 * Different feeds know different things about the same CVE: KEV knows about
 * exploitation but not CVSS, NVD knows CVSS but not exploitation, EPSS knows
 * only a probability. A blind upsert would let whichever ran last erase the
 * others' data, so incoming nulls fall back to the stored value.
 *
 * The read-then-write is deliberate rather than a dynamically-shaped `upsert`:
 * varying the key set per row makes Prisma emit a differently-shaped query each
 * time, which the local dev Postgres proxy rejects with
 * `08P01 bind message supplies N parameters, but prepared statement "" requires 0`.
 * A fixed shape is both portable and clearer about the merge.
 */
async function upsertVulnerabilities(rows: ParsedVulnerability[]): Promise<number> {
  let count = 0;
  for (const v of rows) {
    if (!/^CVE-\d{4}-\d+$/i.test(v.cveId)) continue;
    const cveId = v.cveId.toUpperCase();

    const existing = await db.vulnerability.findUnique({ where: { cveId } });

    if (existing) {
      await db.vulnerability.update({
        where: { cveId },
        data: {
          description: v.description ?? existing.description,
          cvssV3: v.cvssV3 ?? existing.cvssV3,
          cvssV4: v.cvssV4 ?? existing.cvssV4,
          epssScore: v.epssScore ?? existing.epssScore,
          // Once a CVE is known-exploited it stays that way; KEV entries are
          // not retracted because a later feed omitted the flag.
          knownExploited: v.knownExploited || existing.knownExploited,
          kevDateAdded: v.kevDateAdded ?? existing.kevDateAdded,
          publishedAt: v.publishedAt ?? existing.publishedAt,
          vendorRefs: v.vendorRefs?.length ? v.vendorRefs : existing.vendorRefs,
        },
      });
    } else {
      await db.vulnerability.create({
        data: {
          cveId,
          description: v.description ?? null,
          cvssV3: v.cvssV3 ?? null,
          cvssV4: v.cvssV4 ?? null,
          epssScore: v.epssScore ?? null,
          knownExploited: v.knownExploited ?? false,
          kevDateAdded: v.kevDateAdded ?? null,
          publishedAt: v.publishedAt ?? null,
          vendorRefs: v.vendorRefs ?? [],
        },
      });
    }
    count++;
  }
  return count;
}

/** Default retention window: "last 2-3 months" per the product decision, in days. */
export const VULN_RETENTION_DAYS = 90;

/**
 * Deletes every vulnerability older than the retention window — strict,
 * including CISA KEV entries. (An earlier version exempted KEV rows on the
 * reasoning that "actively exploited" stays relevant regardless of age; the
 * product call landed the other way — a self-hosted single-tenant instance
 * would rather see a short, current list than carry Log4Shell forever. If
 * that changes back, gate this on `knownExploited: false`.)
 *
 * Age is judged strictly by `publishedAt` — the CVE's own vintage, which is
 * what actually shows up in the UI. `kevDateAdded` (when CISA flagged it) was
 * tried as a fallback for rows with no NVD publish date, but that let a CVE
 * from 2008 stay on a "last 3 months" list just because CISA re-flagged it
 * recently — exactly the stale-looking noise this is meant to remove. A row
 * with no `publishedAt` is now treated as unknown-age and pruned too, rather
 * than kept indefinitely for lack of a date to judge it by.
 */
export async function pruneOldVulnerabilities(
  retentionDays: number = VULN_RETENTION_DAYS,
): Promise<number> {
  const cutoff = new Date(Date.now() - retentionDays * 86_400_000);
  const result = await db.vulnerability.deleteMany({
    where: {
      OR: [{ publishedAt: { lt: cutoff } }, { publishedAt: null }],
    },
  });
  return result.count;
}

/**
 * Auto-links news to tracked actors and CVEs by scanning title + summary.
 *
 * Actor matching uses names *and* aliases, since a vendor blog will say
 * "Midnight Blizzard" where we track "APT29". Campaign matching is exact-name
 * only — campaigns don't have an alias table, and campaign names ("SolarWinds
 * Supply Chain Compromise") are distinctive enough not to need one. Both are
 * word-boundary matched to avoid "APT29" firing on "APT2".
 *
 * Exported (not just used by `ingestNews`) so `scripts/relink-news.ts` can
 * recompute links for already-ingested news after new actors/campaigns are
 * added — otherwise a campaign added today would never link to an article
 * ingested yesterday, even though the article names it.
 */
export async function linkNewsItem(title: string, summary: string | null) {
  const haystack = `${title} ${summary ?? ""}`;

  const cveIds = [
    ...new Set(
      (haystack.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((c) => c.toUpperCase()),
    ),
  ];

  const [actors, campaigns] = await Promise.all([
    db.threatActor.findMany({
      select: { id: true, name: true, aliases: { select: { alias: true } } },
    }),
    db.campaign.findMany({ select: { id: true, name: true } }),
  ]);

  const matchesAny = (names: string[]) =>
    names.some((n) => {
      if (n.length < 4) return false; // too short to match safely
      const escaped = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(`\\b${escaped}\\b`, "i").test(haystack);
    });

  const linkedActorIds = actors
    .filter((a) => matchesAny([a.name, ...a.aliases.map((x) => x.alias)]))
    .map((a) => a.id);

  const linkedCampaignIds = campaigns
    .filter((c) => matchesAny([c.name]))
    .map((c) => c.id);

  return { cveIds, linkedActorIds, linkedCampaignIds };
}

async function ingestNews(sourceId: string, xml: string): Promise<{ created: number; duped: number }> {
  const items = parseRss(xml);
  let created = 0;
  let duped = 0;

  for (const item of items) {
    const existing = await db.newsItem.findUnique({ where: { url: item.url } });
    if (existing) {
      duped++;
      continue;
    }

    const { cveIds, linkedActorIds, linkedCampaignIds } = await linkNewsItem(
      item.title,
      item.summary,
    );

    // Relevance drives dashboard ordering: named actors, campaigns and CVEs
    // matter more than general coverage.
    const relevanceScore = Math.min(
      100,
      linkedActorIds.length * 25 + linkedCampaignIds.length * 20 + cveIds.length * 15,
    );

    await db.newsItem.create({
      data: {
        title: item.title,
        url: item.url,
        summary: item.summary,
        publishedAt: item.publishedAt,
        sourceId,
        relevanceScore,
        linkedActorIds,
        linkedCveIds: cveIds,
        linkedCampaignIds,
        tags: cveIds.length ? ["cve"] : [],
      },
    });
    created++;
  }

  return { created, duped };
}

async function runHandler(
  handler: FeedHandler,
  source: { id: string; url: string | null; defaultConfidence: number; defaultTlp: never },
): Promise<{ ingested: number; duped: number; message: string }> {
  const url = source.url;
  if (!url) return { ingested: 0, duped: 0, message: "No URL configured" };

  switch (handler) {
    case "kev": {
      const res = await fetchFeed(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const rows = parseKev(await res.json());
      const n = await upsertVulnerabilities(rows);
      return { ingested: n, duped: 0, message: `${n} known-exploited CVEs` };
    }

    case "epss": {
      const res = await fetchFeed(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      // Served gzipped; fetch only auto-decompresses when the server sets
      // Content-Encoding, which this one does not.
      const text = url.endsWith(".gz") ? gunzipSync(buf).toString("utf8") : buf.toString("utf8");
      const scores = parseEpss(text);

      // ~280k rows. Only update CVEs we already track — storing every EPSS score
      // would balloon the table with vulnerabilities nobody has asked about.
      const known = await db.vulnerability.findMany({ select: { cveId: true } });
      const knownSet = new Set(known.map((k) => k.cveId));
      const relevant = scores.filter((s) => knownSet.has(s.cveId));

      for (const s of relevant) {
        await db.vulnerability.update({
          where: { cveId: s.cveId },
          data: { epssScore: s.epssScore },
        });
      }
      return {
        ingested: relevant.length,
        duped: scores.length - relevant.length,
        message: `${relevant.length} scored of ${scores.length} available`,
      };
    }

    case "nvd-recent": {
      // Last 24h only; the full NVD corpus is far too large for an hourly job.
      const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
      const u = new URL(url);
      u.searchParams.set("lastModStartDate", since);
      u.searchParams.set("lastModEndDate", new Date().toISOString());
      u.searchParams.set("resultsPerPage", "500");

      const res = await fetchFeed(u.toString(), { headers: nvdHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const rows = parseNvd(await res.json());
      const n = await upsertVulnerabilities(rows);

      // Piggybacks on the hourly cadence rather than its own schedule — a
      // cheap, indexed delete that keeps the table from growing unbounded as
      // this same job pulls in the full public CVE stream hour after hour.
      const pruned = await pruneOldVulnerabilities();

      return {
        ingested: n,
        duped: 0,
        message: `${n} CVEs updated${pruned > 0 ? `, ${pruned} stale CVEs pruned` : ""}`,
      };
    }

    case "urlhaus": {
      const res = await fetchFeed(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const rows = parseCsv(await res.text());
      const parsed = rows
        .map((r) => parseIndicator(r.url ?? ""))
        .filter((p): p is NonNullable<typeof p> => p !== null);
      const report = await ingestParsed(parsed, {
        sourceId: source.id,
        confidence: source.defaultConfidence,
        tlp: source.defaultTlp,
        severity: "HIGH",
        tags: ["urlhaus", "malware-distribution"],
      });
      return {
        ingested: report.created,
        duped: report.updated + report.duplicatesInInput,
        message: `${report.created} new URLs`,
      };
    }

    case "threatfox": {
      const res = await fetchFeed(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as Record<string, { ioc_value?: string }[]>;
      const values = Object.values(body)
        .flat()
        .map((e) => e?.ioc_value)
        .filter((v): v is string => Boolean(v));
      const parsed = values
        .map((v) => parseIndicator(v))
        .filter((p): p is NonNullable<typeof p> => p !== null);
      const report = await ingestParsed(parsed, {
        sourceId: source.id,
        confidence: source.defaultConfidence,
        tlp: source.defaultTlp,
        severity: "HIGH",
        tags: ["threatfox"],
      });
      return {
        ingested: report.created,
        duped: report.updated + report.duplicatesInInput,
        message: `${report.created} new IOCs`,
      };
    }

    case "feodo": {
      const res = await fetchFeed(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { ip_address?: string; malware?: string }[];
      const parsed = body
        .map((e) => parseIndicator(e.ip_address ?? ""))
        .filter((p): p is NonNullable<typeof p> => p !== null);
      const report = await ingestParsed(parsed, {
        sourceId: source.id,
        confidence: source.defaultConfidence,
        tlp: source.defaultTlp,
        severity: "CRITICAL",
        tags: ["feodo", "c2"],
      });
      return {
        ingested: report.created,
        duped: report.updated + report.duplicatesInInput,
        message: `${report.created} new C2 IPs`,
      };
    }

    case "otx-pulses": {
      const key = getSecret("otx");
      if (!key) return { ingested: 0, duped: 0, message: "OTX_API_KEY not set" };

      const res = await fetchFeed(`${url}?limit=20&page=1`, {
        headers: { "X-OTX-API-KEY": key },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as {
        results?: { name?: string; indicators?: { indicator?: string }[] }[];
      };
      const values = (body.results ?? [])
        .flatMap((p) => p.indicators ?? [])
        .map((i) => i?.indicator)
        .filter((v): v is string => Boolean(v));
      const parsed = values
        .map((v) => parseIndicator(v))
        .filter((p): p is NonNullable<typeof p> => p !== null);
      const report = await ingestParsed(parsed, {
        sourceId: source.id,
        confidence: source.defaultConfidence,
        tlp: source.defaultTlp,
        tags: ["otx"],
      });
      return {
        ingested: report.created,
        duped: report.updated + report.duplicatesInInput,
        message: `${report.created} new IOCs from ${body.results?.length ?? 0} pulses`,
      };
    }

    case "rss-news": {
      const res = await fetchFeed(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const { created, duped } = await ingestNews(source.id, await res.text());
      return { ingested: created, duped, message: `${created} new articles` };
    }

    default:
      return { ingested: 0, duped: 0, message: `No handler for ${handler}` };
  }
}

export async function runFeed(sourceId: string): Promise<FeedRunResult> {
  const source = await db.source.findUnique({ where: { id: sourceId } });
  if (!source) {
    return {
      sourceId,
      sourceName: "(unknown)",
      ok: false,
      itemsIngested: 0,
      itemsDuped: 0,
      message: "Source not found",
    };
  }

  const catalog = findCatalogSource(source.name);
  const handler = (catalog?.handler ??
    (source.parserConfig as { handler?: FeedHandler } | null)?.handler) as
    | FeedHandler
    | undefined;

  if (!handler) {
    const message = "No handler — this source cannot run automatically";
    await db.source.update({
      where: { id: sourceId },
      data: { lastRunAt: new Date(), lastStatus: "skipped", lastError: message },
    });
    return {
      sourceId,
      sourceName: source.name,
      ok: false,
      itemsIngested: 0,
      itemsDuped: 0,
      message,
    };
  }

  try {
    const result = await runHandler(handler, {
      id: source.id,
      url: source.url,
      defaultConfidence: source.defaultConfidence,
      defaultTlp: source.defaultTlp as never,
    });

    await db.source.update({
      where: { id: sourceId },
      data: {
        lastRunAt: new Date(),
        lastStatus: "ok",
        lastError: null,
        itemsIngested: { increment: result.ingested },
        itemsDuped: { increment: result.duped },
      },
    });

    return {
      sourceId,
      sourceName: source.name,
      ok: true,
      itemsIngested: result.ingested,
      itemsDuped: result.duped,
      message: result.message,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await db.source.update({
      where: { id: sourceId },
      data: {
        lastRunAt: new Date(),
        lastStatus: "error",
        lastError: message,
        errorCount: { increment: 1 },
      },
    });
    return {
      sourceId,
      sourceName: source.name,
      ok: false,
      itemsIngested: 0,
      itemsDuped: 0,
      message,
    };
  }
}

/** Used by the seeder and the settings UI to install the catalogue. */
export async function installCatalog(): Promise<number> {
  const { FEED_CATALOG } = await import("@/lib/feeds/catalog");
  let count = 0;
  for (const s of FEED_CATALOG) {
    await db.source.upsert({
      where: { name: s.name },
      update: {
        url: s.url,
        type: s.type,
        schedule: s.schedule,
        defaultConfidence: s.defaultConfidence,
        defaultTlp: s.defaultTlp,
        decayHalfLifeDays: s.decayHalfLifeDays,
        parserConfig: { handler: s.handler, description: s.description },
      },
      create: {
        name: s.name,
        type: s.type,
        url: s.url,
        enabled: true,
        schedule: s.schedule,
        defaultConfidence: s.defaultConfidence,
        defaultTlp: s.defaultTlp,
        decayHalfLifeDays: s.decayHalfLifeDays,
        parserConfig: { handler: s.handler, description: s.description },
      },
    });
    count++;
  }
  return count;
}

export { ingestText };
