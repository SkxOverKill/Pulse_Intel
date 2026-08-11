import { PrismaClient } from "@/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

// Prisma 7 requires an explicit driver adapter — the bundled query engine is gone.
function createClient(connectionString: string) {
  return new PrismaClient({
    // Explicit, bounded pool. `prisma dev` recommends max 10.
    //
    // Note: intermittent `P1017 / ConnectionClosed` errors show up in the dev
    // server log when other Prisma clients (a `next build`, a seed script) run
    // against the local dev Postgres at the same time — several pools of 10
    // against one small server. It has not been reproduced by an idle
    // connection alone (tested up to a 60s gap, with and without idle expiry),
    // so the cause is believed to be connection pressure rather than idle
    // expiry, and it has not been seen against a normal Postgres. Revisit if it
    // appears in production; do not assume this config fixed it.
    adapter: new PrismaPg({
      connectionString,
      max: 10,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 10_000,
    }),
    log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });
}

// Next.js dev server hot-reloads modules, which would otherwise open a new pool
// on every edit until Postgres refuses connections.
const globalForPrisma = globalThis as unknown as {
  prisma: ReturnType<typeof createClient> | undefined;
};

function getDb(): ReturnType<typeof createClient> {
  const cached = globalForPrisma.prisma;
  if (cached) return cached;

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is not set. Copy .env.example to .env.");
  }

  const client = createClient(connectionString);
  if (process.env.NODE_ENV !== "production") {
    globalForPrisma.prisma = client;
  }
  return client;
}

// Lazily initialised on first property access. Module load must not throw when
// DATABASE_URL is absent, or `next build` — which evaluates route modules while
// collecting page data — fails on a machine that hasn't stood up Postgres yet
// (a documented README sanity check). The connection is created, and the clear
// error thrown, on the first actual database call instead.
export const db = new Proxy({} as ReturnType<typeof createClient>, {
  get: (_target, prop) => Reflect.get(getDb(), prop),
});
