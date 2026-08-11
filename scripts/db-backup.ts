import "dotenv/config";

import { mkdir } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { spawn } from "node:child_process";

const DEFAULT_BACKUP_DIR = "backups";

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
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

  console.log(`Backup complete: ${basename(output)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
