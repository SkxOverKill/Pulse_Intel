/**
 * Offline migration helper.
 *
 * `prisma migrate dev` does not work against the local Prisma Postgres dev
 * server (`npm run db:dev`): its schema-engine RPCs fail with P1017, and
 * introspection fails with `prepared statement "s3" already exists`. Diffing
 * from the migrations directory avoids both, so that is what this uses.
 *
 *   1. diff prisma/migrations against schema.prisma
 *   2. check the result for drops of raw-SQL indexes (see below)
 *   3. write it to prisma/migrations/<timestamp>_<name>/migration.sql
 *   4. apply it, and record it in _prisma_migrations
 *
 * Once you are on a normal Postgres, use `npm run db:migrate` instead — but the
 * drift guard in step 2 still applies there, so read that section first.
 *
 * Usage: npm run db:migrate:offline -- <migration_name>
 */
import "dotenv/config";

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * Indexes created by raw SQL in 20260721010000_search_indexes. They do not
 * appear in schema.prisma, so Prisma sees them as drift and emits DROP INDEX for
 * every one of them on every diff. Dropping them turns each fuzzy search into a
 * sequential scan — a silent performance cliff with no error to notice.
 *
 * If you add more raw-SQL indexes, add them here too.
 */
const RAW_SQL_INDEXES = [
  "ThreatActor_name_trgm_idx",
  "ActorAlias_alias_trgm_idx",
  "Campaign_name_trgm_idx",
  "Malware_name_trgm_idx",
  "Tool_name_trgm_idx",
  "Indicator_normalized_trgm_idx",
  "Vulnerability_cve_trgm_idx",
  "Technique_name_trgm_idx",
  "Report_fts_idx",
  "ThreatActor_fts_idx",
  "Campaign_fts_idx",
  "NewsItem_fts_idx",
  "Technique_fts_idx",
];

const name = process.argv[2];
if (!name) {
  console.error("Usage: npm run db:migrate:offline -- <migration_name>");
  process.exit(1);
}

function prisma(args: string[]): string {
  return execFileSync("npx", ["prisma", ...args], {
    encoding: "utf8",
    shell: process.platform === "win32",
  });
}

const scratch = join(tmpdir(), `pulse-migrate-${randomUUID()}.sql`);

try {
  prisma([
    "migrate",
    "diff",
    "--from-migrations",
    "prisma/migrations",
    "--to-schema",
    "prisma/schema.prisma",
    "--script",
    "-o",
    scratch,
  ]);

  const sql = readFileSync(scratch, "utf8").trim();
  if (!sql || sql.startsWith("-- This is an empty migration")) {
    console.log("No schema changes to apply.");
    process.exit(0);
  }

  const clobbered = RAW_SQL_INDEXES.filter((idx) =>
    new RegExp(`DROP INDEX\\s+(IF EXISTS\\s+)?"${idx}"`, "i").test(sql),
  );

  if (clobbered.length > 0) {
    console.error(
      `\nRefusing to apply: this diff would drop ${clobbered.length} raw-SQL index(es):\n`,
    );
    for (const idx of clobbered) console.error(`    ${idx}`);
    console.error(
      [
        "",
        "These are created by raw SQL and do not exist in schema.prisma, so Prisma",
        "reports them as drift every time. Dropping them would silently turn fuzzy",
        "and full-text search into sequential scans.",
        "",
        "Write the migration by hand instead: take the generated SQL below, delete",
        "the DROP INDEX statements for the indexes listed above, and keep the rest.",
        "",
        "--- generated SQL ---",
        sql,
      ].join("\n"),
    );
    process.exit(1);
  }

  const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const dir = join("prisma", "migrations", `${stamp}_${name}`);
  mkdirSync(dir, { recursive: true });

  const file = join(dir, "migration.sql");
  writeFileSync(file, `${sql}\n`);
  console.log(`Wrote ${file}`);

  prisma(["db", "execute", "--file", file]);
  console.log("Applied.");

  record(`${stamp}_${name}`, file);
} finally {
  rmSync(scratch, { force: true });
}

function record(migrationName: string, file: string) {
  const checksum = createHash("sha256").update(readFileSync(file)).digest("hex");
  const mark = join(tmpdir(), `pulse-mark-${randomUUID()}.sql`);
  writeFileSync(
    mark,
    `INSERT INTO "_prisma_migrations"
       ("id","checksum","finished_at","migration_name","started_at","applied_steps_count")
     VALUES
       ('${randomUUID()}','${checksum}',now(),'${migrationName}',now(),1);`,
  );
  prisma(["db", "execute", "--file", mark]);
  rmSync(mark, { force: true });
  console.log(`Recorded ${migrationName} in migration history.`);
}
