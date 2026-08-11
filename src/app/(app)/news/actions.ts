"use server";

import { revalidatePath } from "next/cache";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { fail, ok, withAction, type ActionResult } from "@/lib/actions";
import { fetchFullArticle } from "@/lib/feeds/article";

const FetchSchema = z.object({ id: z.string().min(1) });

/**
 * Analyst-triggered, one item at a time — not run automatically at ingest.
 * See the copyright/ToS note in lib/feeds/article.ts for why this is a
 * deliberate per-request action rather than a background job.
 */
export async function fetchArticleContent(
  _prev: ActionResult<{ content: string }>,
  formData: FormData,
): Promise<ActionResult<{ content: string }>> {
  return withAction(
    { role: "ANALYST", schema: FetchSchema, formData },
    async (input, user) => {
      const item = await db.newsItem.findUnique({ where: { id: input.id } });
      if (!item) return fail("News item not found.");

      let content: string | null;
      try {
        content = await fetchFullArticle(item.url);
      } catch (err) {
        return fail(
          `Could not fetch the article: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      if (!content) {
        return fail(
          "Couldn't extract article text from that page — it may render content client-side, or block automated requests.",
        );
      }

      await db.newsItem.update({
        where: { id: item.id },
        data: { content, contentFetchedAt: new Date() },
      });

      await audit({
        action: "IMPORT",
        entityType: "NewsItem",
        entityId: item.id,
        userId: user.id,
        changes: { fetchedArticle: true, url: item.url },
      });

      revalidatePath(`/news/${item.id}`);
      return ok({ content });
    },
  );
}
