/**
 * One-time (or ad-hoc) vulnerability retention cleanup.
 *
 * Deletes every vulnerability (including CISA KEV) older than the retention
 * window. This now also runs automatically every hour as part of the
 * "nvd-recent" feed job (src/lib/feeds/run.ts) — this script exists for an
 * immediate cleanup after changing the window, or right after a large
 * backfill.
 *
 *   npm run vuln:prune              # 90 days (2-3 months)
 *   npm run vuln:prune -- --days 60
 */
import "dotenv/config";

import { db } from "../src/lib/db";
import { pruneOldVulnerabilities, VULN_RETENTION_DAYS } from "../src/lib/feeds/run";

const daysArg = process.argv.indexOf("--days");
const days = daysArg !== -1 ? Number(process.argv[daysArg + 1]) : VULN_RETENTION_DAYS;

async function main() {
  const before = await db.vulnerability.count();

  console.log(`Pruning all vulnerabilities older than ${days} days…`);
  console.log(`  before: ${before} total`);

  const pruned = await pruneOldVulnerabilities(days);
  const after = await db.vulnerability.count();

  console.log(`  pruned: ${pruned}`);
  console.log(`  after:  ${after} total`);

  await db.$disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
