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

/**
 * Auto-links news to tracked actors and CVEs by scanning title + summary.
 *
 * Actor matching uses names *and* aliases, since a vendor blog will say
 * "Midnight Blizzard" where we track "APT29". Word-boundary matched to avoid
 * "APT29" firing on "APT2".
 */
async function linkNewsItem(title: string, summary: string | null) {
  const haystack = `${title} ${summary ?? ""}`;

  const cveIds = [
    ...new Set(
      (haystack.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((c) => c.toUpperCase()),
    ),
  ];

  const actors = await db.threatActor.findMany({
    select: { id: true, name: true, aliases: { select: { alias: true } } },
  });

  const linkedActorIds = actors
    .filter((a) => {
      const names = [a.name, ...a.aliases.map((x) => x.alias)];
      return names.some((n) => {
        if (n.length < 4) return false; // too short to match safely
        const escaped = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        return new RegExp(`\\b${escaped}\\b`, "i").test(haystack);
      });
    })
    .map((a) => a.id);

  return { cveIds, linkedActorIds };
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

    const { cveIds, linkedActorIds } = await linkNewsItem(item.title, item.summary);

    // Relevance drives dashboard ordering: named actors and CVEs matter more
    // than general coverage.
    const relevanceScore = Math.min(
      100,
      linkedActorIds.length * 25 + cveIds.length * 15,
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

      const res = await fetchFeed(u.toString());
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const rows = parseNvd(await res.json());
      const n = await upsertVulnerabilities(rows);
      return { ingested: n, duped: 0, message: `${n} CVEs updated` };
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
      const key = process.env.OTX_API_KEY;
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
