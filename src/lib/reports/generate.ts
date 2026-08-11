/**
 * Scheduled report generation — the automated equivalent of an analyst writing
 * "what changed this week." Queries the same signals as the dashboard
 * (src/app/(app)/page.tsx) but scoped to a window instead of "right now", and
 * renders markdown instead of tiles.
 *
 * No `server-only`: the worker runs this outside a bundler, same reason
 * src/lib/hunting and src/lib/feeds carry none.
 */
import { db } from "@/lib/db";

export type ReportPeriod = { since: Date; until: Date };

export type GeneratedReport = {
  title: string;
  summary: string;
  body: string;
  tags: string[];
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

/**
 * Builds a markdown summary of everything that changed in `[period.since,
 * period.until)`. Read-only — the caller decides whether and how to persist it.
 */
export async function generateSummaryReport(
  period: ReportPeriod,
): Promise<GeneratedReport> {
  const { since, until } = period;
  const createdInWindow = { gte: since, lt: until };

  const [
    newIndicatorsBySeverity,
    newActors,
    newCampaigns,
    newKev,
    huntAlerts,
    erroringFeeds,
  ] = await Promise.all([
    db.indicator.groupBy({
      by: ["severity"],
      where: { whitelisted: false, createdAt: createdInWindow },
      _count: { _all: true },
    }),
    db.threatActor.findMany({
      where: { createdAt: createdInWindow },
      select: { name: true, motivation: true },
      orderBy: { name: "asc" },
    }),
    db.campaign.findMany({
      where: { createdAt: createdInWindow },
      select: { name: true, status: true },
      orderBy: { name: "asc" },
    }),
    db.vulnerability.findMany({
      where: { knownExploited: true, kevDateAdded: createdInWindow },
      select: { cveId: true, epssScore: true },
      orderBy: [{ epssScore: { sort: "desc", nulls: "last" } }],
      take: 20,
    }),
    db.huntAlert.findMany({
      where: { createdAt: createdInWindow },
      select: { newCount: true, hunt: { select: { name: true } } },
      orderBy: { createdAt: "desc" },
    }),
    db.source.findMany({
      where: { enabled: true, lastStatus: "error" },
      select: { name: true, lastError: true },
    }),
  ]);

  const severityCounts = new Map(
    newIndicatorsBySeverity.map((r) => [r.severity, r._count._all]),
  );
  const totalNewIndicators = newIndicatorsBySeverity.reduce(
    (sum, r) => sum + r._count._all,
    0,
  );

  const days = Math.max(1, Math.round((until.getTime() - since.getTime()) / 86_400_000));
  const dateLabel = until.toISOString().slice(0, 10);

  const lines: string[] = [];

  lines.push(`# Intelligence summary — ${dateLabel}`);
  lines.push("");
  lines.push(
    `Covering the ${days} day${days === 1 ? "" : "s"} from ${since.toISOString().slice(0, 10)} to ${dateLabel}.`,
  );
  lines.push("");

  lines.push("## New indicators");
  if (totalNewIndicators === 0) {
    lines.push("No new indicators in this period.");
  } else {
    lines.push(`${totalNewIndicators} new indicator(s), by severity:`);
    lines.push("");
    for (const sev of SEVERITY_ORDER) {
      const count = severityCounts.get(sev);
      if (count) lines.push(`- ${sev}: ${count}`);
    }
  }
  lines.push("");

  lines.push("## Threat actor activity");
  if (newActors.length === 0 && newCampaigns.length === 0) {
    lines.push("No new actors or campaigns tracked in this period.");
  } else {
    for (const a of newActors) {
      lines.push(`- New actor tracked: **${a.name}** (${a.motivation.toLowerCase()})`);
    }
    for (const c of newCampaigns) {
      lines.push(`- New campaign: **${c.name}** (${c.status.toLowerCase()})`);
    }
  }
  lines.push("");

  lines.push("## CISA KEV additions");
  if (newKev.length === 0) {
    lines.push("No new Known Exploited Vulnerabilities added in this period.");
  } else {
    for (const v of newKev) {
      const epss = v.epssScore != null ? ` — EPSS ${(v.epssScore * 100).toFixed(0)}%` : "";
      lines.push(`- ${v.cveId}${epss}`);
    }
  }
  lines.push("");

  lines.push("## Hunt alerts");
  if (huntAlerts.length === 0) {
    lines.push("No hunt alerts fired in this period.");
  } else {
    for (const a of huntAlerts) {
      lines.push(`- **${a.hunt.name}** — ${a.newCount} new match(es)`);
    }
  }
  lines.push("");

  lines.push("## Feed health");
  if (erroringFeeds.length === 0) {
    lines.push("All enabled feeds are healthy.");
  } else {
    for (const f of erroringFeeds) {
      lines.push(`- **${f.name}**: ${f.lastError ?? "erroring"}`);
    }
  }

  const summaryParts: string[] = [];
  if (totalNewIndicators > 0) summaryParts.push(`${totalNewIndicators} new indicators`);
  if (newKev.length > 0) summaryParts.push(`${newKev.length} new KEV CVEs`);
  if (huntAlerts.length > 0) summaryParts.push(`${huntAlerts.length} hunt alert(s)`);
  if (erroringFeeds.length > 0) summaryParts.push(`${erroringFeeds.length} feed(s) erroring`);
  const summary =
    summaryParts.length > 0
      ? summaryParts.join(", ")
      : "No significant changes in this period.";

  return {
    title: `Intelligence summary — ${dateLabel}`,
    summary,
    body: lines.join("\n"),
    tags: ["scheduled-report"],
  };
}
