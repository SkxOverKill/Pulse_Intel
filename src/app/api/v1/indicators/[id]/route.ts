import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";
import { activeIndicatorWhere } from "@/lib/ioc/decay";

/**
 * GET /api/v1/indicators/:id
 *
 * A whitelisted indicator 404s exactly like a nonexistent one — the public API
 * must not let a client distinguish "doesn't exist" from "exists but is
 * whitelisted" (design rule 3: never exported, alerted, or otherwise surfaced
 * outside the internal working view).
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireApiKey(req, "indicators:read");
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const indicator = await db.indicator.findFirst({
    where: {
      id,
      ...activeIndicatorWhere(),
    },
    include: {
      source: { select: { name: true } },
      enrichments: {
        select: { provider: true, verdict: true, score: true, fetchedAt: true },
      },
    },
  });

  if (!indicator || indicator.whitelisted) {
    return NextResponse.json(
      { error: "Indicator not found." },
      { status: 404, headers: auth.headers },
    );
  }

  return NextResponse.json(
    {
      data: {
        id: indicator.id,
        type: indicator.type,
        value: indicator.value,
        confidence: indicator.confidence,
        severity: indicator.severity,
        tlp: indicator.tlp,
        tags: indicator.tags,
        source: indicator.source?.name ?? null,
        firstSeen: indicator.firstSeen,
        lastSeen: indicator.lastSeen,
        expiresAt: indicator.expiresAt,
        enrichments: indicator.enrichments,
      },
    },
    { headers: auth.headers },
  );
}
