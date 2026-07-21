/**
 * Offline migration helper.
 *
 * `prisma migrate dev` does not work against the local Prisma Postgres dev
 * server (`npm run db:dev`): its schema-engine RPCs fail with P1017 /
 * "unexpected message from server". Introspection and `db execute` do work, so
 * this script reproduces the same workflow through those:
 *
 *   1. diff the live database against schema.prisma
 *   2. write the delta to prisma/migrations/<timestamp>_<name>/migration.sql
 *   3. apply it
 *   4. record it in _prisma_migrations so history stays consistent
 *
 * Once you are on a normal Postgres (Docker or WSL), drop this and use
 * `npm run db:migrate` instead — this is a workaround, not the destination.
 *
 * Usage: npm run db:migrate:offline -- <migration_name>
 */
import "dotenv/config";

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

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
    "--from-config-datasource",
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

  const stamp = new Date()
    .toISOString()
    .replace(/[-:T]/g, "")
    .slice(0, 14);
  const dir = join("prisma", "migrations", `${stamp}_${name}`);
  mkdirSync(dir, { recursive: true });

  const file = join(dir, "migration.sql");
  writeFileSync(file, `${sql}\n`);
  console.log(`Wrote ${file}`);

  prisma(["db", "execute", "--file", file]);
  console.log("Applied.");

  const checksum = createHash("sha256")
    .update(readFileSync(file))
    .digest("hex");

  const mark = join(tmpdir(), `pulse-mark-${randomUUID()}.sql`);
  writeFileSync(
    mark,
    `INSERT INTO "_prisma_migrations"
       ("id","checksum","finished_at","migration_name","started_at","applied_steps_count")
     VALUES
       ('${randomUUID()}','${checksum}',now(),'${stamp}_${name}',now(),1);`,
  );
  prisma(["db", "execute", "--file", mark]);
  rmSync(mark, { force: true });

  console.log(`Recorded ${stamp}_${name} in migration history.`);
} finally {
  rmSync(scratch, { force: true });
}
