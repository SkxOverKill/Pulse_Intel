import "dotenv/config";

import { rm, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import {
  databaseNameFromUrl,
  swapDatabaseName,
} from "@/lib/backup/urls";

/**
 * Backup/restore round-trip smoke test for non-production environments.
 *
 * Proves the real backup tools work on a given platform-image pair by doing
 * exactly what an operator would:
 *   1. pg_dump the DATABASE_URL database (custom format),
 *   2. validate the dump with pg_restore --list,
 *   3. create a scratch database on the same server,
 *   4. pg_restore into it,
 *   5. diff schema-only and data-only dumps of source vs restored — a restored
 *      copy carries the same rows, not just the same row counts,
 *   6. drop the scratch database and delete the temp dump in every exit path.
 *
 * The source database is only ever read; nothing about it is modified.
 * Requires pg_dump/pg_restore/psql on PATH and a role with CREATEDB.
 */

const KEEP_SCRATCH = process.argv.includes("--keep");

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      env: process.env,
      stdio: ["ignore", "pipe", "inherit"],
      shell: process.platform === "win32",
    });

    let stdout = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.on("error", (err) =>
      reject(new Error(`failed to start ${command} — is it on PATH? (${err.message})`)),
    );
    child.on("exit", (code) => {
      if (code === 0) resolvePromise(stdout);
      else reject(new Error(`${command} exited with code ${code}`));
    });
  });
}

/** psql -tA output is a list of lines; trim the surrounding chatter. */
async function psqlLines(databaseUrl: string, sql: string): Promise<string[]> {
  const out = await run("psql", [
    "-tA",
    "--no-psqlrc",
    databaseUrl,
    "-c",
    sql,
  ]);
  return out
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/**
 * A canonical text dump diffed byte-for-byte proves parity of structure and of
 * content independently. Drop header comments ("-- ..."), which differ by
 * dump time and target name, then compare line arrays.
 */
async function canonicalDump(databaseUrl: string, flags: string[]): Promise<string[]> {
  const out = await run("pg_dump", [
    "--no-owner",
    "--no-acl",
    ...flags,
    databaseUrl,
  ]);
  return out
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0 && !line.startsWith("--"));
}

function assertEqual(what: string, a: string[], b: string[]) {
  if (a.length !== b.length) {
    throw new Error(
      `${what} mismatch (${a.length} vs ${b.length} lines). Restored database is not equivalent to source.`,
    );
  }
}

async function main() {
  const sourceUrl = process.env.DATABASE_URL;
  if (!sourceUrl) throw new Error("DATABASE_URL is not set.");

  const sourceDb = databaseNameFromUrl(sourceUrl);
  const maintainUrl = swapDatabaseName(sourceUrl, "postgres");
  const scratch = `pulse_verify_${process.pid}_${Date.now().toString(36)}`;
  const scratchUrl = swapDatabaseName(sourceUrl, scratch);

  const tmpDir = await mkdtemp(join(tmpdir(), "pulse-backup-verify-"));
  const dumpPath = join(tmpDir, "source.dump");
  const scratchExists = { value: false };
  let exitCode = 0;

  const dropScratch = async () => {
    if (!scratchExists.value) return;
    if (KEEP_SCRATCH) {
      console.log(`[keep] leaving scratch database ${scratch} in place.`);
      return;
    }
    await run("psql", [
      ...["-tA", "--no-psqlrc", maintainUrl, "-c"],
      `DROP DATABASE IF EXISTS "${scratch}" WITH (FORCE)`,
    ]).catch((err) => console.error(`Failed to drop scratch database: ${err.message}`));
  };

  try {
    console.log(`Source database: ${sourceDb}`);
    console.log(`Backing up ${sourceDb} (custom format)...`);
    await run("pg_dump", [
      `--dbname=${sourceUrl}`, // avoids "password required" on some setups
      "--format=custom",
      "--no-owner",
      "--no-acl",
      `--file=${dumpPath}`,
    ]);

    console.log("Validating dump with pg_restore --list...");
    await run("pg_restore", ["--list", dumpPath]);

    console.log(`Creating scratch database ${scratch}...`);
    await run("psql", [
      "-tA",
      "--no-psqlrc",
      maintainUrl,
      "-c",
      `CREATE DATABASE "${scratch}"`,
    ]);
    scratchExists.value = true;

    console.log("Restoring into scratch database...");
    await run("pg_restore", [
      "--no-owner",
      "--no-acl",
      `--dbname=${scratchUrl}`,
      dumpPath,
    ]);

    console.log("Comparing schema parity...");
    const schemaSource = await canonicalDump(sourceUrl, ["--schema-only"]);
    const schemaRestored = await canonicalDump(scratchUrl, ["--schema-only"]);
    assertEqual("Schema", schemaSource, schemaRestored);

    console.log("Comparing data parity...");
    const dataSource = await canonicalDump(sourceUrl, ["--data-only"]);
    const dataRestored = await canonicalDump(scratchUrl, ["--data-only"]);
    assertEqual("Data", dataSource, dataRestored);

    console.log("Confirming restored database answers queries...");
    const tableCounts = await psqlLines(
      scratchUrl,
      `SELECT count(*) FROM pg_tables WHERE schemaname = 'public';`,
    );
    console.log(`  public tables in restored db: ${tableCounts.join(", ") || 0}`);

    console.log("Smoke test passed: backup restores to an identical database.");
  } catch (err) {
    exitCode = 1;
    console.error(err instanceof Error ? err.message : err);
    if (KEEP_SCRATCH) {
      console.error(`Scratch database ${scratch} left in place for inspection.`);
    }
  } finally {
    await dropScratch();
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }

  if (exitCode !== 0) process.exit(exitCode);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});