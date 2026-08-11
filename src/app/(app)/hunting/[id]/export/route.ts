import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { getCurrentUser } from "@/lib/auth/dal";
import { validateHuntQuery } from "@/lib/hunting/schema";
import { compileWhere } from "@/lib/hunting/compile";
import {
  EXPORT_FORMATS,
  formatExport,
  type ExportFormat,
  type ExportIndicator,
} from "@/lib/export/formats";

const EXPORT_CAP = 50_000;

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const user = await getCurrentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  const { id } = await params;
  const format = (req.nextUrl.searchParams.get("format") ?? "csv") as ExportFormat;
  const meta = EXPORT_FORMATS.find((f) => f.id === format);
  if (!meta) {
    return NextResponse.json({ error: "Unknown format." }, { status: 400 });
  }

  const hunt = await db.huntQuery.findUnique({
    where: { id },
    select: { id: true, name: true, query: true },
  });
  if (!hunt) {
    return NextResponse.json({ error: "Hunt not found." }, { status: 404 });
  }

  const validated = validateHuntQuery(hunt.query);
  if (!validated.ok) {
    return NextResponse.json(
      { error: `Invalid hunt query: ${validated.errors.join("; ")}` },
      { status: 400 },
    );
  }

  const rows = await db.indicator.findMany({
    where: compileWhere(validated.ast),
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

  await audit({
    action: "EXPORT",
    entityType: "HuntQuery",
    entityId: hunt.id,
    userId: user.id,
    changes: { format, count: indicators.length, name: hunt.name },
  });

  const stamp = new Date().toISOString().slice(0, 10);
  return new NextResponse(formatExport(indicators, format), {
    headers: {
      "Content-Type": `${meta.contentType}; charset=utf-8`,
      "Content-Disposition": `attachment; filename="pulse-hunt-${hunt.id}-${stamp}.${meta.extension}"`,
      "Cache-Control": "no-store",
    },
  });
}
