import "dotenv/config";

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function hasFlag(name: string): boolean {
  return process.argv.includes(name);
}

function run(command: string, args: string[]): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      env: process.env,
      stdio: ["ignore", "inherit", "inherit"],
      shell: process.platform === "win32",
    });

    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited with code ${code}`));
    });
  });
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is not set.");

  const input = argValue("--input");
  if (!input) throw new Error("Missing --input <backup.dump>.");

  const backupPath = resolve(input);
  if (!existsSync(backupPath)) throw new Error(`Backup file not found: ${backupPath}`);

  if (!hasFlag("--yes")) {
    throw new Error(
      "Restore is destructive. Re-run with --yes after confirming the target DATABASE_URL.",
    );
  }

  console.log(`Restoring PostgreSQL backup into DATABASE_URL target: ${backupPath}`);
  await run("pg_restore", [
    "--clean",
    "--if-exists",
    "--no-owner",
    "--no-acl",
    "--dbname",
    databaseUrl,
    backupPath,
  ]);
  console.log("Restore complete.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
