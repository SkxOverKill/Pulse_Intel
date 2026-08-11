import "dotenv/config";

import { mkdir, readdir, unlink } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { spawn } from "node:child_process";

const DEFAULT_BACKUP_DIR = "backups";
const DEFAULT_RETAIN = 7;

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function hasFlag(name: string): boolean {
  return process.argv.includes(name);
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function run(command: string, args: string[], env = process.env): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      env,
      stdio: ["ignore", "inherit", "inherit"],
      shell: process.platform === "win32",
    });

    child.on("error", (err) => reject(new Error(`failed to start ${command}: ${err.message}`)));
    child.on("exit", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited with code ${code}`));
    });
  });
}

/** Dumps are timestamped with ISO time (dashes, no colons) so name sort === age sort. */
const BACKUP_NAME_RE = /^pulse-intelligence-\d{4}-\d{2}-\d{2}T[\d-]+Z\.(dump|dump\.enc)$/;

async function pruneOldBackups(outputDir: string, keep: number): Promise<void> {
  const entries = (await readdir(outputDir))
    .filter((name) => BACKUP_NAME_RE.test(name))
    .sort();
  const excess = entries.length - keep;
  for (const name of entries.slice(0, excess)) {
    await unlink(join(outputDir, name));
    console.log(`Pruned old backup: ${name}`);
  }
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is not set.");

  const outputDir = resolve(argValue("--dir") ?? DEFAULT_BACKUP_DIR);
  await mkdir(outputDir, { recursive: true });

  const output =
    argValue("--output") ??
    resolve(outputDir, `pulse-intelligence-${timestamp()}.dump`);

  console.log(`Creating PostgreSQL custom-format backup: ${output}`);
  await run("pg_dump", [
    "--format=custom",
    "--no-owner",
    "--no-acl",
    "--file",
    output,
    databaseUrl,
  ]);

  // Smoke-test the dump with pg_restore --list before the backup is trusted
  // (or encrypted): a corrupt custom-format file fails here, not at restore
  // time when it is already too late.
  if (hasFlag("--verify")) {
    await run("pg_restore", ["--list", output]);
    console.log("Backup verified: pg_restore can read the dump.");
  }

  const encrypted = hasFlag("--encrypt");
  if (encrypted) {
    const passphrase = process.env.BACKUP_PASSPHRASE;
    if (!passphrase) {
      await unlink(output).catch(() => {});
      throw new Error("--encrypt requires BACKUP_PASSPHRASE to be set (kept out of argv on purpose).");
    }
    const encryptedPath = `${output}.enc`;
    await run("openssl", [
      "enc",
      "-aes-256-cbc",
      "-pbkdf2",
      "-iter",
      "100000",
      "-salt",
      "-pass",
      "env:BACKUP_PASSPHRASE",
      "-in",
      output,
      "-out",
      encryptedPath,
    ]);
    await unlink(output);
    console.log(`Encrypted backup: ${basename(encryptedPath)}`);
  }

  const retainRaw = argValue("--retain") ?? String(DEFAULT_RETAIN);
  const retain = Number(retainRaw);
  if (!Number.isFinite(retain) || retain < 1) {
    throw new Error(`--retain must be a positive integer, got "${retainRaw}".`);
  }
  await pruneOldBackups(outputDir, retain);
  console.log(`Backup complete. Retaining ${retain} backups in ${outputDir}.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
