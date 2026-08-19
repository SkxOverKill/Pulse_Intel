"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit, diff } from "@/lib/audit";
import { fail, ok, parseList, withAction, type ActionResult } from "@/lib/actions";
import { ingestText, type IngestReport } from "@/lib/ioc/ingest";

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] as const;

const BulkSchema = z.object({
  text: z.string().min(1, { error: "Paste at least one indicator." }),
  severity: z.enum(SEVERITIES).default("MEDIUM"),
  tlp: z.enum(TLPS).default("AMBER"),
  confidence: z.coerce.number().int().min(0).max(100).default(50),
  tags: z.string().optional(),
  sourceId: z.string().optional(),
});

export type BulkState = ActionResult<IngestReport>;

export async function bulkIngest(
  _prev: BulkState,
  formData: FormData,
): Promise<BulkState> {
  const result = await withAction(
    { role: "ANALYST", schema: BulkSchema, formData },
    async (input, user) => {
      const report = await ingestText(input.text, {
        severity: input.severity,
        tlp: input.tlp,
        confidence: input.confidence,
        tags: parseList(input.tags),
        sourceId: input.sourceId || undefined,
        userId: user.id,
      });

      await audit({
        action: "IMPORT",
        entityType: "Indicator",
        userId: user.id,
        changes: {
          created: report.created,
          updated: report.updated,
          whitelisted: report.whitelisted,
          unparsed: report.unparsed.length,
        },
      });

      return ok(report);
    },
  );

  if (result.ok) revalidatePath("/indicators");
  return result;
}

const UpdateConfidenceSchema = z.object({
  id: z.string().min(1),
  confidence: z.coerce.number().int().min(0).max(100),
  // A single unchecked checkbox arrives absent, checked arrives as "on".
  lock: z.coerce.boolean().default(false),
});

/**
 * Sets an indicator's confidence by hand. Setting `lock` pins the value so
 * enrichment (recomputeIndicatorConfidence) stops overwriting it — an analyst
 * who knows an IOC is confirmed is telling the platform "don't argue with me".
 * Unchecking lock hands the value back to provider scores.
 */
export async function updateIndicatorConfidence(
  _prev: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  return withAction(
    { role: "ANALYST", schema: UpdateConfidenceSchema, formData },
    async (input, user) => {
      const before = await db.indicator.findUnique({
        where: { id: input.id },
        select: { confidence: true, confidenceLocked: true },
      });
      if (!before) return fail("Indicator not found.");

      const after = { confidence: input.confidence, confidenceLocked: input.lock };
      if (before.confidence === after.confidence && before.confidenceLocked === after.confidenceLocked) {
        return ok();
      }

      await db.indicator.update({ where: { id: input.id }, data: after });
      await audit({
        action: "UPDATE",
        entityType: "Indicator",
        entityId: input.id,
        userId: user.id,
        changes: diff(before, after),
      });
      revalidatePath(`/indicators/${input.id}`);
      revalidatePath("/indicators");
      return ok();
    },
  );
}

export async function setWhitelisted(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({
        id: z.string().min(1),
        whitelisted: z.coerce.boolean().default(false),
      }),
      formData,
    },
    async (input, user) => {
      await db.indicator.update({
        where: { id: input.id },
        data: { whitelisted: input.whitelisted },
      });
      await audit({
        action: "UPDATE",
        entityType: "Indicator",
        entityId: input.id,
        userId: user.id,
        changes: { whitelisted: input.whitelisted },
      });
      return ok();
    },
  );
  revalidatePath(`/indicators/${id}`);
  revalidatePath("/indicators");
}

export async function deleteIndicator(formData: FormData): Promise<void> {
  const result = await withAction(
    { role: "ADMIN", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      const indicator = await db.indicator.findUnique({ where: { id: input.id } });
      if (!indicator) return fail("Already deleted.");
      await db.indicator.delete({ where: { id: input.id } });
      await audit({
        action: "DELETE",
        entityType: "Indicator",
        entityId: input.id,
        userId: user.id,
        changes: { value: indicator.value, type: indicator.type },
      });
      return ok();
    },
  );

  if (!result.ok) redirect(`/indicators/${String(formData.get("id") ?? "")}`);
  revalidatePath("/indicators");
  redirect("/indicators");
}
