"use server";

import { revalidatePath } from "next/cache";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { fail, ok, withAction, type ActionResult } from "@/lib/actions";
import { PRIORITY, enqueueEnrichment, enqueueFeed } from "@/lib/queue/queues";

/**
 * Queues every un-enriched indicator.
 *
 * Capped per invocation: queueing 100k jobs that the free tier could not clear
 * for months would be dishonest about what is actually going to happen.
 */
const BATCH_CAP = 5000;

export async function enrichAllPending(
  _prev: ActionResult<{ queued: number }>,
  formData: FormData,
): Promise<ActionResult<{ queued: number }>> {
  return withAction(
    { role: "ANALYST", schema: z.object({}), formData },
    async (_input, user) => {
      const pending = await db.indicator.findMany({
        where: { whitelisted: false, enrichments: { none: {} } },
        select: { id: true },
        take: BATCH_CAP,
      });

      if (pending.length === 0) {
        return fail("Nothing to enrich — every indicator already has results.");
      }

      const queued = await enqueueEnrichment(
        pending.map((i) => ({ indicatorId: i.id })),
        PRIORITY.BULK,
      );

      await audit({
        action: "ENRICH",
        entityType: "Indicator",
        userId: user.id,
        changes: { queued },
      });

      revalidatePath("/enrichment");
      return ok({ queued });
    },
  );
}

/** Analyst-triggered single enrichment — jumps ahead of any bulk backlog. */
export async function enrichIndicatorNow(formData: FormData): Promise<void> {
  const id = String(formData.get("indicatorId") ?? "");
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({ indicatorId: z.string().min(1) }),
      formData,
    },
    async (input, user) => {
      await enqueueEnrichment(
        [{ indicatorId: input.indicatorId, force: true }],
        PRIORITY.INTERACTIVE,
      );
      await audit({
        action: "ENRICH",
        entityType: "Indicator",
        entityId: input.indicatorId,
        userId: user.id,
        changes: { priority: "interactive" },
      });
      return ok();
    },
  );
  revalidatePath(`/indicators/${id}`);
}

/** Manual feed run from the feeds page. */
export async function runFeedNow(formData: FormData): Promise<void> {
  await withAction(
    { role: "ANALYST", schema: z.object({ sourceId: z.string().min(1) }), formData },
    async (input, user) => {
      await enqueueFeed(input.sourceId, false);
      await audit({
        action: "IMPORT",
        entityType: "Source",
        entityId: input.sourceId,
        userId: user.id,
        changes: { trigger: "manual" },
      });
      return ok();
    },
  );
  revalidatePath("/feeds");
}
