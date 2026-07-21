"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit, diff } from "@/lib/audit";
import { fail, ok, parseList, withAction, type ActionResult } from "@/lib/actions";
import { slugify } from "@/lib/utils";

const TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] as const;

const ReportSchema = z.object({
  id: z.string().optional(),
  title: z.string().min(3, { error: "Title must be at least 3 characters." }).trim(),
  summary: z.string().trim().optional(),
  body: z.string().min(1, { error: "A report needs a body." }),
  sourceUrl: z.url({ error: "Must be a valid URL." }).optional().or(z.literal("")),
  tags: z.string().optional(),
  tlp: z.enum(TLPS).default("AMBER"),
  confidence: z.coerce.number().int().min(0).max(100).default(50),
  published: z.coerce.boolean().default(false),
});

export async function saveReport(
  _prev: ActionResult<void>,
  formData: FormData,
): Promise<ActionResult<void>> {
  let redirectTo: string | null = null;

  const result = await withAction(
    { role: "ANALYST", schema: ReportSchema, formData },
    async (input, user) => {
      const data = {
        title: input.title,
        slug: slugify(input.title),
        summary: input.summary || null,
        body: input.body,
        sourceUrl: input.sourceUrl || null,
        tags: parseList(input.tags),
        tlp: input.tlp,
        confidence: input.confidence,
        published: input.published,
        // Stamp publication time on first publish only, so editing a published
        // report doesn't silently reorder the feed.
        publishedAt: input.published ? new Date() : null,
      };

      if (input.id) {
        const before = await db.report.findUnique({ where: { id: input.id } });
        if (!before) return fail("That report no longer exists.");

        const after = await db.report.update({
          where: { id: input.id },
          data: {
            ...data,
            publishedAt: before.publishedAt ?? (input.published ? new Date() : null),
          },
        });
        await audit({
          action: "UPDATE",
          entityType: "Report",
          entityId: after.id,
          userId: user.id,
          changes: diff(before, after),
        });
        redirectTo = `/reports/${after.id}`;
      } else {
        const created = await db.report.create({
          data: { ...data, authorId: user.id },
        });
        await audit({
          action: "CREATE",
          entityType: "Report",
          entityId: created.id,
          userId: user.id,
          changes: { title: created.title },
        });
        redirectTo = `/reports/${created.id}`;
      }
      return ok();
    },
  );

  if (!result.ok) return result;
  revalidatePath("/reports");
  redirect(redirectTo!);
}

export async function deleteReport(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  const result = await withAction(
    { role: "ADMIN", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      const report = await db.report.findUnique({ where: { id: input.id } });
      if (!report) return fail("Already deleted.");
      await db.report.delete({ where: { id: input.id } });
      await audit({
        action: "DELETE",
        entityType: "Report",
        entityId: input.id,
        userId: user.id,
        changes: { title: report.title },
      });
      return ok();
    },
  );
  if (!result.ok) redirect(`/reports/${id}`);
  revalidatePath("/reports");
  redirect("/reports");
}

/**
 * Extracts every IOC found in the report body and ingests it, linking each to
 * the report. This is the workflow that makes reports worth writing in-platform
 * rather than in a document.
 */
export async function extractIndicators(formData: FormData): Promise<void> {
  const reportId = String(formData.get("reportId") ?? "");

  await withAction(
    {
      role: "ANALYST",
      schema: z.object({ reportId: z.string().min(1) }),
      formData,
    },
    async (input, user) => {
      const report = await db.report.findUnique({ where: { id: input.reportId } });
      if (!report) return fail("Report not found.");

      const { ingestText } = await import("@/lib/ioc/ingest");
      const { parseBulk } = await import("@/lib/ioc/normalize");

      // Ingest first so every indicator exists, then link them all.
      await ingestText(report.body, {
        confidence: report.confidence,
        tlp: report.tlp,
        userId: user.id,
      });

      const { parsed } = parseBulk(report.body);
      if (parsed.length) {
        const rows = await db.indicator.findMany({
          where: {
            OR: parsed.map((p) => ({
              type: p.type,
              normalizedValue: p.normalizedValue,
            })),
          },
          select: { id: true },
        });

        await db.reportIndicator.createMany({
          data: rows.map((r) => ({
            reportId: input.reportId,
            indicatorId: r.id,
            confidence: report.confidence,
            addedById: user.id,
          })),
          skipDuplicates: true,
        });
      }

      await audit({
        action: "IMPORT",
        entityType: "Report",
        entityId: input.reportId,
        userId: user.id,
        changes: { extractedIndicators: parsed.length },
      });
      return ok();
    },
  );

  revalidatePath(`/reports/${reportId}`);
}
