/**
 * Scheduled report execution. Shared by the server ("Run now") and the worker
 * (a scheduled run) — no `server-only`, no request-scoped APIs, same reason as
 * src/lib/hunting/run.ts.
 */
import { db } from "@/lib/db";
import { slugify } from "@/lib/utils";
import { generateSummaryReport } from "@/lib/reports/generate";

export type ScheduledReportRunResult =
  | { ok: true; reportId: string }
  | { ok: false; error: string };

/**
 * Runs a scheduled report: generates a summary of everything since the last
 * run (or since the schedule was created, on a first run) and files it as a
 * `Report` row. `authorId` is left unset — an absent author is how the UI and
 * the API tell a system-generated report from an analyst-authored one, rather
 * than a fabricated "system" user that would need its own account and role.
 */
export async function runScheduledReport(
  scheduledReportId: string,
): Promise<ScheduledReportRunResult> {
  const scheduled = await db.scheduledReport.findUnique({
    where: { id: scheduledReportId },
  });
  if (!scheduled) return { ok: false, error: "Scheduled report not found." };

  const since = scheduled.lastRunAt ?? scheduled.createdAt;
  const until = new Date();

  const generated = await generateSummaryReport({ since, until });

  // Same collision risk as an analyst typing the same title twice: the slug
  // carries the date so back-to-back runs on the same day are still unique
  // rather than throwing on the report's @@unique(slug).
  const slugBase = `${scheduled.name}-${until.toISOString().slice(0, 10)}`;
  let slug = slugify(slugBase);
  if (await db.report.findUnique({ where: { slug } })) {
    slug = `${slug}-${until.getTime()}`;
  }

  const report = await db.report.create({
    data: {
      title: `${scheduled.name}: ${generated.title}`,
      slug,
      summary: generated.summary,
      body: generated.body,
      published: true,
      publishedAt: until,
      tags: generated.tags,
      confidence: 100, // Generated from the platform's own data, not a claim.
    },
  });

  await db.scheduledReport.update({
    where: { id: scheduledReportId },
    data: { lastRunAt: until },
  });

  return { ok: true, reportId: report.id };
}
