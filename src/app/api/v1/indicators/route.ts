import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";
import {
  EXPORT_FORMATS,
  exportHeader,
  exportBatch,
  exportFooter,
  createExportState,
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

  // Attribution pivot filters — lets SOAR playbooks pull all IOCs for a
  // given actor or campaign without needing to know which indicator IDs to ask for.
  const actorId = params.get("actorId");
  const campaignId = params.get("campaignId");

  // Confidence floor — skip low-confidence indicators for high-fidelity exports.
  const minConfidenceRaw = params.get("minConfidence");
  const minConfidence = minConfidenceRaw !== null ? Number(minConfidenceRaw) : null;
  if (minConfidence !== null && (isNaN(minConfidence) || minConfidence < 0 || minConfidence > 100)) {
    return NextResponse.json({ error: "minConfidence must be 0-100." }, { status: 400 });
  }

  // `?since=` accepts an ISO date string — pulls indicators last seen after
  // that date. Useful for incremental sync ("give me everything new since yesterday").
  const sinceRaw = params.get("since");
  let since: Date | null = null;
  if (sinceRaw) {
    since = new Date(sinceRaw);
    if (isNaN(since.getTime())) {
      return NextResponse.json(
        { error: "since must be a valid ISO 8601 date string." },
        { status: 400 },
      );
    }
  }

  const now = new Date();

  const where = {
    whitelisted: false,
    ...activeIndicatorWhere(now),
    ...(q ? { normalizedValue: { contains: q.toLowerCase() } } : {}),
    ...(type.value ? { type: type.value } : {}),
    ...(severity.value ? { severity: severity.value } : {}),
    ...(tag ? { tags: { has: tag } } : {}),
    ...(minConfidence !== null ? { confidence: { gte: minConfidence } } : {}),
    ...(since ? { lastSeen: { gte: since } } : {}),
    // Attribution filters are AND — if both are specified, indicator must be
    // linked to BOTH the actor and the campaign.
    ...(actorId ? { actors: { some: { actorId } } } : {}),
    ...(campaignId ? { campaigns: { some: { campaignId } } } : {}),
  };

  if (format !== "json") {
    const meta = EXPORT_FORMATS.find((f) => f.id === format)!;
    const totalCount = await db.indicator.count({ where });
    const cappedCount = Math.min(totalCount, 50_000);

    // A Response/NextResponse body must yield bytes, not strings — enqueuing a
    // raw string throws "Received non-Uint8Array chunk" at read time. Encode
    // every chunk before enqueuing.
    const encoder = new TextEncoder();

    const stream = new ReadableStream({
      async start(controller) {
        const state = createExportState();
        controller.enqueue(encoder.encode(exportHeader(format, cappedCount)));

        const BATCH_SIZE = 1_000;
        let skip = 0;

        while (skip < cappedCount) {
          const rows = await db.indicator.findMany({
            where,
            orderBy: { lastSeen: "desc" },
            skip,
            take: Math.min(BATCH_SIZE, cappedCount - skip),
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
          });

          if (rows.length === 0) break;

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

          const batchStr = exportBatch(indicators, format, state);
          if (batchStr) controller.enqueue(encoder.encode(batchStr));

          skip += rows.length;
        }

        controller.enqueue(encoder.encode(exportFooter(format, state)));
        controller.close();
      },
    });

    return new NextResponse(stream, {
      headers: {
        ...auth.headers,
        "Content-Type": `${meta.contentType}; charset=utf-8`,
      },
    });
  }

  const skip = (page - 1) * pageSize;
  const take = pageSize;
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
    db.indicator.count({ where }),
  ]);

  return NextResponse.json(
    {
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
    },
    { headers: auth.headers },
  );
}
