import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";
import { parsePageParams, parseCampaignStatus } from "@/lib/api/query";

const PAGE_SIZE_DEFAULT = 50;
const PAGE_SIZE_MAX = 200;

/** GET /api/v1/campaigns — the public, programmatic equivalent of /campaigns. */
export async function GET(req: NextRequest) {
  const auth = await requireApiKey(req, "campaigns:read");
  if (!auth.ok) return auth.response;

  const params = req.nextUrl.searchParams;
  const pagination = parsePageParams(params, {
    pageSize: PAGE_SIZE_DEFAULT,
    maxPageSize: PAGE_SIZE_MAX,
  });
  if (!pagination.ok) return pagination.response;
  const { page, pageSize } = pagination.value;

  const status = parseCampaignStatus(params.get("status"));
  if (!status.ok) return status.response;

  const where = status.value !== null ? { status: status.value } : {};

  const [rows, total] = await Promise.all([
    db.campaign.findMany({
      where,
      orderBy: { startDate: { sort: "desc", nulls: "last" } },
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: {
        _count: { select: { actors: true, techniques: true, indicators: true } },
      },
    }),
    db.campaign.count({ where }),
  ]);

  return NextResponse.json(
    {
      data: rows.map((c) => ({
        id: c.id,
        name: c.name,
        slug: c.slug,
        description: c.description,
        status: c.status,
        startDate: c.startDate,
        endDate: c.endDate,
        targetSectors: c.targetSectors,
        targetCountries: c.targetCountries,
        confidence: c.confidence,
        tlp: c.tlp,
        actorCount: c._count.actors,
        techniqueCount: c._count.techniques,
        indicatorCount: c._count.indicators,
      })),
      page,
      pageSize,
      total,
    },
    { headers: auth.headers },
  );
}
