import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { getCurrentUser } from "@/lib/auth/dal";
import { audit } from "@/lib/audit";
import {
  EXPORT_FORMATS,
  formatExport,
  type ExportFormat,
  type ExportIndicator,
} from "@/lib/export/formats";

// A single export must not try to serialize the entire table into memory. This
// is generous for a working set; a full-database dump is a Phase 8 streaming
// concern, not an interactive download.
const EXPORT_CAP = 50_000;

/**
 * Streams a filtered indicator set in the requested format. The filters mirror
 * the /indicators list (q / type / severity) so "export what I'm looking at"
 * does exactly that — with one non-negotiable addition: `whitelisted: false` is
 * forced regardless of the query. Whitelisted IOCs are never exported (design
 * rule 3), so there is deliberately no way to ask for them here.
 */
export async function GET(req: NextRequest) {
  const user = await getCurrentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  const params = req.nextUrl.searchParams;
  const format = (params.get("format") ?? "csv") as ExportFormat;
  const meta = EXPORT_FORMATS.find((f) => f.id === format);
  if (!meta) {
    return NextResponse.json({ error: "Unknown format." }, { status: 400 });
  }

  const q = params.get("q");
  const type = params.get("type");
  const severity = params.get("severity");

  const where = {
    whitelisted: false,
    ...(q ? { normalizedValue: { contains: q.toLowerCase() } } : {}),
    ...(type ? { type: type as never } : {}),
    ...(severity ? { severity: severity as never } : {}),
  };

  const rows = await db.indicator.findMany({
    where,
    orderBy: { lastSeen: "desc" },
    take: EXPORT_CAP,
    select: {
      type: true,
      value: true,
      normalizedValue: true,
      confidence: true,
      severity: true,
      tlp: true,
      tags: true,
      firstSeen: true,
      lastSeen: true,
      source: { select: { name: true } },
    },
  });

  const indicators: ExportIndicator[] = rows.map((r) => ({
    type: r.type,
    value: r.value,
    normalizedValue: r.normalizedValue,
    confidence: r.confidence,
    severity: r.severity,
    tlp: r.tlp,
    tags: r.tags,
    firstSeen: r.firstSeen,
    lastSeen: r.lastSeen,
    source: r.source?.name ?? null,
  }));

  const body = formatExport(indicators, format);

  await audit({
    action: "EXPORT",
    entityType: "Indicator",
    userId: user.id,
    changes: { format, count: indicators.length, filters: { q, type, severity } },
  });

  const stamp = new Date().toISOString().slice(0, 10);
  return new NextResponse(body, {
    headers: {
      "Content-Type": `${meta.contentType}; charset=utf-8`,
      "Content-Disposition": `attachment; filename="pulse-indicators-${stamp}.${meta.extension}"`,
      "Cache-Control": "no-store",
    },
  });
}
