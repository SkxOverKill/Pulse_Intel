/**
 * End-to-end verification of scheduled reports against the real database.
 *
 * Creates a throwaway ScheduledReport, runs it twice back to back, and checks
 * the properties that matter: a Report row is actually filed, it has no author
 * (so the UI reads it as generated, not analyst-claimed), its body reflects
 * real counts from the DB, and — the anti-noise property, same as hunting — a
 * second run immediately after the first covers an empty window and still
 * succeeds without erroring or duplicating unrelated data. Cleans up after.
 *
 *   npm run verify:reports
 */
import "dotenv/config";

import { db } from "../src/lib/db";
import { generateSummaryReport } from "../src/lib/reports/generate";
import { runScheduledReport } from "../src/lib/reports/run";

let failures = 0;
function check(label: string, pass: boolean, detail = "") {
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
  if (!pass) failures++;
}

async function main() {
  console.log("Scheduled report verification\n");

  console.log("generator");
  const dbIndicatorCount = await db.indicator.count({
    where: { whitelisted: false, createdAt: { gte: new Date(0) } },
  });
  const generated = await generateSummaryReport({ since: new Date(0), until: new Date() });
  check("generates a title and markdown body", generated.title.length > 0 && generated.body.length > 0);
  check("body is a markdown heading, not HTML", generated.body.startsWith("# "));
  check("tags the report as a scheduled-report", generated.tags.includes("scheduled-report"));
  const totalLine = generated.body.match(/(\d+) new indicator\(s\), by severity/);
  if (dbIndicatorCount > 0) {
    check(
      "body's new-indicator total matches the DB over an all-time window",
      !!totalLine && Number(totalLine[1]) === dbIndicatorCount,
      `body=${totalLine?.[1]} db=${dbIndicatorCount}`,
    );
  } else {
    console.log("  SKIP  no indicators in this DB to cross-check the count against");
  }

  console.log("\nrunner (throwaway schedule)");
  const scheduled = await db.scheduledReport.create({
    data: { name: "__verify_reports", schedule: "0 8 * * 1" },
  });

  try {
    const first = await runScheduledReport(scheduled.id);
    check("first run succeeds", first.ok);

    if (first.ok) {
      const report = await db.report.findUnique({ where: { id: first.reportId } });
      check("a Report row was actually filed", report != null);
      check("the filed report has no author", report?.authorId == null);
      check("the filed report is published", report?.published === true);
      check("the filed report carries the scheduled-report tag", !!report?.tags.includes("scheduled-report"));
      check(
        "the report title references the schedule's name",
        !!report?.title.startsWith(scheduled.name),
      );
    }

    const reloaded = await db.scheduledReport.findUnique({ where: { id: scheduled.id } });
    check("lastRunAt was stamped", reloaded?.lastRunAt != null);

    // Second run immediately after: the window [firstRun, now) should be
    // essentially empty of new activity, and — critically — this must not
    // throw on a duplicate slug or a bad date range.
    const second = await runScheduledReport(scheduled.id);
    check("second run (empty window) also succeeds", second.ok);
    if (second.ok) {
      const secondReport = await db.report.findUnique({ where: { id: second.reportId } });
      check(
        "second run files a distinct report (no slug collision)",
        !!secondReport && secondReport.id !== (first.ok ? first.reportId : null),
      );
    }

    const reportCount = await db.report.count({
      where: { title: { startsWith: scheduled.name } },
    });
    check("exactly two reports were filed for this schedule", reportCount === 2, `${reportCount}`);
  } finally {
    await db.report.deleteMany({ where: { title: { startsWith: "__verify_reports" } } });
    await db.scheduledReport.delete({ where: { id: scheduled.id } });
    console.log("\ncleaned up throwaway schedule and its reports");
  }

  console.log(failures === 0 ? "\nAll checks passed." : `\n${failures} check(s) FAILED.`);
  await db.$disconnect();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
