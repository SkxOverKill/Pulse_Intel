/**
 * One-time NVD catch-up: backfills recently *published* CVEs.
 *
 * The hourly feed job (src/lib/feeds/run.ts, "nvd-recent") only looks at a
 * rolling 24h `lastModStartDate` window — correct for staying current once the
 * data is current, but useless for digging out of a backlog, since it can only
 * ever see the last day. This script instead pages through everything NVD
 * *published* in the last N days, so a stale database catches up in one run
 * instead of trickling in 24 hours at a time.
 *
 * Requires NVD_API_KEY in .env (free, instant, https://nvd.nist.gov/developers/
 * request-an-api-key) — without one this would take ~10x longer per page and
 * risk 403s under the keyless 5-req/30s limit.
 *
 *   npm run cve:catchup            # last 30 days
 *   npm run cve:catchup -- --days 90
 */
import "dotenv/config";

import { db } from "../src/lib/db";
import { parseNvd } from "../src/lib/feeds/parsers";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RESULTS_PER_PAGE = 2000;
// NVD's own guidance: even with a key, space requests out rather than bursting
// the full 50/30s allowance — a one-time backfill has no reason to race it.
const REQUEST_DELAY_MS = 6_000;
const MAX_PAGES = 20; // guards against a runaway loop; 20 * 2000 = 40k CVEs

const daysArg = process.argv.indexOf("--days");
const DAYS = daysArg !== -1 ? Number(process.argv[daysArg + 1]) : 30;

const apiKey = process.env.NVD_API_KEY;
if (!apiKey) {
  console.error("NVD_API_KEY is not set in .env — add it first (see .env.example).");
  process.exit(1);
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function upsert(rows: ReturnType<typeof parseNvd>): Promise<{ created: number; updated: number }> {
  let created = 0;
  let updated = 0;
  for (const v of rows) {
    const existing = await db.vulnerability.findUnique({ where: { cveId: v.cveId } });
    if (existing) {
      await db.vulnerability.update({
        where: { cveId: v.cveId },
        data: {
          description: v.description ?? existing.description,
          cvssV3: v.cvssV3 ?? existing.cvssV3,
          cvssV4: v.cvssV4 ?? existing.cvssV4,
          // Backfill is publish-date driven and never sees KEV status —
          // preserve whatever the KEV feed already recorded.
          knownExploited: existing.knownExploited,
          kevDateAdded: existing.kevDateAdded,
          publishedAt: v.publishedAt ?? existing.publishedAt,
          vendorRefs: v.vendorRefs?.length ? v.vendorRefs : existing.vendorRefs,
        },
      });
      updated++;
    } else {
      await db.vulnerability.create({
        data: {
          cveId: v.cveId,
          description: v.description ?? null,
          cvssV3: v.cvssV3 ?? null,
          cvssV4: v.cvssV4 ?? null,
          publishedAt: v.publishedAt ?? null,
          vendorRefs: v.vendorRefs ?? [],
        },
      });
      created++;
    }
  }
  return { created, updated };
}

async function main() {
  const end = new Date();
  const start = new Date(end.getTime() - DAYS * 86_400_000);
  console.log(
    `Fetching CVEs published ${start.toISOString().slice(0, 10)} → ${end.toISOString().slice(0, 10)}…\n`,
  );

  let startIndex = 0;
  let totalResults = Infinity;
  let page = 0;
  let created = 0;
  let updated = 0;

  while (startIndex < totalResults && page < MAX_PAGES) {
    const url = new URL(NVD_URL);
    url.searchParams.set("pubStartDate", start.toISOString());
    url.searchParams.set("pubEndDate", end.toISOString());
    url.searchParams.set("resultsPerPage", String(RESULTS_PER_PAGE));
    url.searchParams.set("startIndex", String(startIndex));

    const res = await fetch(url, { headers: { apiKey: apiKey! } });
    if (!res.ok) {
      throw new Error(`NVD HTTP ${res.status}: ${await res.text().catch(() => "")}`);
    }
    const body = (await res.json()) as { totalResults?: number };
    totalResults = body.totalResults ?? 0;

    const rows = parseNvd(body);
    const result = await upsert(rows);
    created += result.created;
    updated += result.updated;

    startIndex += RESULTS_PER_PAGE;
    page++;
    console.log(
      `  page ${page}: +${result.created} new, ${result.updated} updated ` +
        `(${Math.min(startIndex, totalResults)}/${totalResults})`,
    );

    if (startIndex < totalResults) await sleep(REQUEST_DELAY_MS);
  }

  console.log(`\nDone. ${created} created, ${updated} updated, ${totalResults} total in range.`);
  await db.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
