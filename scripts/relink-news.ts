/**
 * Re-links every existing NewsItem to actors/campaigns/CVEs.
 *
 * `linkNewsItem` only runs at ingest time (src/lib/feeds/run.ts), so an
 * article ingested before a campaign existed never gets linked to it later —
 * the match only happens once, against whatever actors/campaigns were tracked
 * that hour. This recomputes links for the whole table against the *current*
 * roster, so adding a new campaign (or actor) makes it retroactively visible
 * on news that already mentioned it.
 *
 * Safe to run any time; cheap enough to run after every seed change.
 *
 *   npm run news:relink
 */
import "dotenv/config";

import { db } from "../src/lib/db";
import { linkNewsItem } from "../src/lib/feeds/run";

async function main() {
  const items = await db.newsItem.findMany({
    select: { id: true, title: true, summary: true },
  });
  console.log(`Re-linking ${items.length} news item(s)…`);

  let changed = 0;
  for (const item of items) {
    const { cveIds, linkedActorIds, linkedCampaignIds } = await linkNewsItem(
      item.title,
      item.summary,
    );
    const relevanceScore = Math.min(
      100,
      linkedActorIds.length * 25 + linkedCampaignIds.length * 20 + cveIds.length * 15,
    );

    await db.newsItem.update({
      where: { id: item.id },
      data: { linkedActorIds, linkedCveIds: cveIds, linkedCampaignIds, relevanceScore },
    });
    changed++;
  }

  console.log(`Done. ${changed} item(s) updated.`);
  await db.$disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
