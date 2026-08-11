import "dotenv/config";

import { existsSync } from "node:fs";
import { unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function hasFlag(name: string): boolean {
  return process.argv.includes(name);
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

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is not set.");

  const input = argValue("--input");
  if (!input) throw new Error("Missing --input <backup.dump[.enc]>.");

  const backupPath = resolve(input);
  if (!existsSync(backupPath)) throw new Error(`Backup file not found: ${backupPath}`);

  if (!hasFlag("--yes")) {
    throw new Error(
      "Restore is destructive. Re-run with --yes after confirming the target DATABASE_URL.",
    );
  }

  let restoreFile = backupPath;
  const tempFiles: string[] = [];

  if (backupPath.endsWith(".enc")) {
    const passphrase = process.env.BACKUP_PASSPHRASE;
    if (!passphrase) {
      throw new Error("Encrypted backup requires BACKUP_PASSPHRASE to be set.");
    }
    restoreFile = `${backupPath}.dec`;
    tempFiles.push(restoreFile);
    console.log("Decrypting backup...");
    await run("openssl", [
      "enc",
      "-d",
      "-aes-256-cbc",
      "-pbkdf2",
      "-iter",
      "100000",
      "-salt",
      "-pass",
      "env:BACKUP_PASSPHRASE",
      "-in",
      backupPath,
      "-out",
      restoreFile,
    ]);
  }

  try {
    // Preflight: prove the dump is a readable custom-format archive before
    // dropping any tables. A corrupt or wrong-format file aborts here while
    // the target database is still intact.
    await run("pg_restore", ["--list", restoreFile]);
    console.log("Backup validated; beginning restore.");

    console.log(`Restoring PostgreSQL backup into DATABASE_URL target: ${backupPath}`);
    await run("pg_restore", [
      "--clean",
      "--if-exists",
      "--no-owner",
      "--no-acl",
      "--dbname",
      databaseUrl,
      restoreFile,
    ]);
    console.log("Restore complete.");
  } finally {
    // The decrypted copy holds plaintext intelligence; never leave it on disk.
    await Promise.all(tempFiles.map((f) => unlink(f).catch(() => {})));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
