import "dotenv/config";

import { PrismaClient } from "../src/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { hash } from "@node-rs/argon2";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL is not set.");

const db = new PrismaClient({
  adapter: new PrismaPg({ connectionString }),
});

const ARGON_OPTS = { memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;

// Dev-only credentials. Overridable so the same seed can bootstrap a real deploy.
const SEED_PASSWORD = process.env.SEED_PASSWORD ?? "PulseAdmin!2026";

const USERS = [
  { email: "admin@pulse.local", name: "Platform Admin", role: "ADMIN" },
  { email: "analyst@pulse.local", name: "Threat Analyst", role: "ANALYST" },
  { email: "viewer@pulse.local", name: "Read Only", role: "READONLY" },
] as const;

async function main() {
  const passwordHash = await hash(SEED_PASSWORD, ARGON_OPTS);

  for (const u of USERS) {
    await db.user.upsert({
      where: { email: u.email },
      // Don't clobber a changed password on re-seed; only ensure the user exists.
      update: { name: u.name, role: u.role },
      create: { email: u.email, name: u.name, role: u.role, passwordHash },
    });
    console.log(`  user  ${u.email.padEnd(22)} ${u.role}`);
  }

  console.log(`\nSeeded ${USERS.length} users with password: ${SEED_PASSWORD}`);
  if (!process.env.SEED_PASSWORD) {
    console.log("These are development defaults — change them before any real use.");
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
