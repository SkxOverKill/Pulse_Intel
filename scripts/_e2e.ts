import "dotenv/config";
import { db } from "../src/lib/db";
import { enqueueEnrichment, PRIORITY } from "../src/lib/queue/queues";
async function main() {
  const ips = await db.indicator.findMany({ where: { type: "IPV4", whitelisted: false, enrichments: { none: {} } }, take: 2, select: { id: true, value: true } });
  const domains = await db.indicator.findMany({ where: { type: "DOMAIN", whitelisted: false, enrichments: { none: {} } }, take: 2, select: { id: true, value: true } });
  const batch = [...ips, ...domains];
  for (const i of batch) console.log("  queue " + i.value);
  console.log(`queued ${await enqueueEnrichment(batch.map(i => ({ indicatorId: i.id })), PRIORITY.INTERACTIVE)} jobs`);
  await db.$disconnect();
}
main().catch(e => { console.error(e.message); process.exit(1); });
