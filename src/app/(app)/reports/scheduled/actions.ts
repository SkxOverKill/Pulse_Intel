"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit, diff } from "@/lib/audit";
import { fail, ok, withAction, type ActionResult } from "@/lib/actions";
import { runScheduledReport } from "@/lib/reports/run";

const ScheduledReportSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(2, { error: "Name must be at least 2 characters." }).trim(),
  description: z.string().trim().optional(),
  schedule: z.string().trim().min(1, { error: "A cron schedule is required." }),
  enabled: z.coerce.boolean().default(true),
});

export async function saveScheduledReport(
  _prev: ActionResult<void>,
  formData: FormData,
): Promise<ActionResult<void>> {
  const result = await withAction(
    { role: "ANALYST", schema: ScheduledReportSchema, formData },
    async (input, user) => {
      const data = {
        name: input.name,
        description: input.description || null,
        schedule: input.schedule,
        enabled: input.enabled,
      };

      if (input.id) {
        const before = await db.scheduledReport.findUnique({ where: { id: input.id } });
        if (!before) return fail("That scheduled report no longer exists.");
        const after = await db.scheduledReport.update({ where: { id: input.id }, data });
        await audit({
          action: "UPDATE",
          entityType: "ScheduledReport",
          entityId: after.id,
          userId: user.id,
          changes: diff(before, after),
        });
      } else {
        const created = await db.scheduledReport.create({
          data: { ...data, ownerId: user.id },
        });
        await audit({
          action: "CREATE",
          entityType: "ScheduledReport",
          entityId: created.id,
          userId: user.id,
          changes: { name: created.name, schedule: created.schedule },
        });
      }
      return ok();
    },
  );

  if (!result.ok) return result;
  revalidatePath("/reports/scheduled");
  redirect("/reports/scheduled");
}

export async function deleteScheduledReport(formData: FormData): Promise<void> {
  await withAction(
    { role: "ANALYST", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      await db.scheduledReport.delete({ where: { id: input.id } });
      await audit({
        action: "DELETE",
        entityType: "ScheduledReport",
        entityId: input.id,
        userId: user.id,
      });
      return ok();
    },
  );
  revalidatePath("/reports/scheduled");
}

export async function toggleScheduledReport(formData: FormData): Promise<void> {
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({ id: z.string().min(1), enabled: z.coerce.boolean().default(false) }),
      formData,
    },
    async (input, user) => {
      await db.scheduledReport.update({
        where: { id: input.id },
        data: { enabled: input.enabled },
      });
      await audit({
        action: "UPDATE",
        entityType: "ScheduledReport",
        entityId: input.id,
        userId: user.id,
        changes: { enabled: input.enabled },
      });
      return ok();
    },
  );
  revalidatePath("/reports/scheduled");
}

/**
 * Runs a scheduled report synchronously — like hunts, this is a handful of
 * count/groupBy queries, cheap enough that "Run now" can return the result on
 * the same request rather than round-tripping through the queue. The queue
 * (reportQueue) exists for the worker's cron scheduler, which needs BullMQ's
 * repeatable-job support — not for one-off manual runs.
 */
export async function runScheduledReportNow(formData: FormData): Promise<void> {
  await withAction(
    { role: "ANALYST", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      const result = await runScheduledReport(input.id);
      if (!result.ok) return fail(result.error);
      await audit({
        action: "UPDATE",
        entityType: "ScheduledReport",
        entityId: input.id,
        userId: user.id,
        changes: { ranNow: true, reportId: result.reportId },
      });
      return ok();
    },
  );
  revalidatePath("/reports/scheduled");
  revalidatePath("/reports");
}
