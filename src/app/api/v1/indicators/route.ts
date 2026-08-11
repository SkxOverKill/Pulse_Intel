import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";
import {
  EXPORT_FORMATS,
  formatExport,
  type ExportFormat,
  type ExportIndicator,
} from "@/lib/export/formats";
import {
  parseIndicatorType,
  parsePageParams,
  parseSeverity,
} from "@/lib/api/query";
import { activeIndicatorWhere } from "@/lib/ioc/decay";

const PAGE_SIZE_DEFAULT = 100;
const PAGE_SIZE_MAX = 500;

/**
 * GET /api/v1/indicators — the public, programmatic equivalent of the
 * /indicators page and its Export menu. Same non-negotiable rule as both:
 * **whitelisted indicators are never returned**, regardless of any filter, so
 * there is no way to construct a request that leaks one (design rule 3).
 *
 * `?format=` reuses the same formatters as the interactive export route
 * (src/app/(app)/indicators/export/route.ts) — one implementation of "what a
 * CSV/STIX/MISP/Snort export looks like", used by both surfaces.
 */
export async function GET(req: NextRequest) {
  const auth = await requireApiKey(req, "indicators:read");
  if (!auth.ok) return auth.response;

  const params = req.nextUrl.searchParams;
  const format = (params.get("format") ?? "json") as ExportFormat | "json";
  if (format !== "json" && !EXPORT_FORMATS.some((f) => f.id === format)) {
    return NextResponse.json({ error: "Unknown format." }, { status: 400 });
  }

  const pagination = parsePageParams(params, {
    pageSize: PAGE_SIZE_DEFAULT,
    maxPageSize: PAGE_SIZE_MAX,
  });
  if (!pagination.ok) return pagination.response;
  const { page, pageSize } = pagination.value;

  const q = params.get("q");
  const type = parseIndicatorType(params.get("type"));
  if (!type.ok) return type.response;
  const severity = parseSeverity(params.get("severity"));
  if (!severity.ok) return severity.response;
  const tag = params.get("tag");
  const now = new Date();

  const where = {
    whitelisted: false,
    ...activeIndicatorWhere(now),
    ...(q ? { normalizedValue: { contains: q.toLowerCase() } } : {}),
    ...(type.value ? { type: type.value } : {}),
    ...(severity.value ? { severity: severity.value } : {}),
    ...(tag ? { tags: { has: tag } } : {}),
  };

  // Non-JSON formats are a full-set export, not a paginated page — matches the
  // interactive export route's behavior (export the filtered view, capped).
  const take = format === "json" ? pageSize : 50_000;
  const skip = format === "json" ? (page - 1) * pageSize : 0;

  const [rows, total] = await Promise.all([
    db.indicator.findMany({
      where,
      orderBy: { lastSeen: "desc" },
      skip,
      take,
      select: {
        id: true,
        type: true,
        value: true,
        normalizedValue: true,
        confidence: true,
        severity: true,
        tlp: true,
        tags: true,
        firstSeen: true,
        lastSeen: true,
        expiresAt: true,
        source: { select: { name: true } },
      },
    }),
    format === "json" ? db.indicator.count({ where }) : Promise.resolve(0),
  ]);

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
    expiresAt: r.expiresAt,
    source: r.source?.name ?? null,
  }));

  if (format !== "json") {
    const meta = EXPORT_FORMATS.find((f) => f.id === format)!;
    return new NextResponse(formatExport(indicators, format), {
      headers: { "Content-Type": `${meta.contentType}; charset=utf-8` },
    });
  }

  return NextResponse.json({
    data: rows.map((r) => ({
      id: r.id,
      type: r.type,
      value: r.value,
      confidence: r.confidence,
      severity: r.severity,
      tlp: r.tlp,
      tags: r.tags,
      source: r.source?.name ?? null,
      firstSeen: r.firstSeen,
      lastSeen: r.lastSeen,
      expiresAt: r.expiresAt,
    })),
    page,
    pageSize,
    total,
  });
}
