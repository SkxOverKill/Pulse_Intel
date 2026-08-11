/** Installs the preconfigured feed catalogue. Idempotent. */
import "dotenv/config";
import { db } from "../src/lib/db";
import { installCatalog } from "../src/lib/feeds/run";

async function main() {
  const n = await installCatalog();
  const sources = await db.source.findMany({
    orderBy: { name: "asc" },
    select: { name: true, type: true, schedule: true, enabled: true },
  });
  console.log(`Installed/updated ${n} sources:\n`);
  for (const s of sources) {
    console.log(`  ${s.enabled ? "on " : "off"} ${s.name.padEnd(42)} ${String(s.type).padEnd(5)} ${s.schedule ?? "manual"}`);
  }
  await db.$disconnect();
}
main().catch((e) => { console.error(e); process.exit(1); });
