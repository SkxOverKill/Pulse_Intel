import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";
import { parsePageParams } from "@/lib/api/query";

const PAGE_SIZE_DEFAULT = 50;
const PAGE_SIZE_MAX = 200;

/**
 * GET /api/v1/campaigns
 *
 * Paginated campaign list with optional status filter.
 *
 * ?status=ACTIVE|SUSPECTED|DORMANT|CONCLUDED
 * ?page=1&pageSize=50
 */
export async function GET(req: NextRequest) {
  const auth = await requireApiKey(req, "actors:read");
  if (!auth.ok) return auth.response;

  const params = req.nextUrl.searchParams;
  const pagination = parsePageParams(params, {
    pageSize: PAGE_SIZE_DEFAULT,
    maxPageSize: PAGE_SIZE_MAX,
  });
  if (!pagination.ok) return pagination.response;
  const { page, pageSize } = pagination.value;

  const VALID_STATUSES = ["ACTIVE", "SUSPECTED", "DORMANT", "CONCLUDED"] as const;
  type CampaignStatus = (typeof VALID_STATUSES)[number];

  const rawStatus = params.get("status");
  let status: CampaignStatus | undefined;
  if (rawStatus) {
    if (!VALID_STATUSES.includes(rawStatus as CampaignStatus)) {
      return NextResponse.json(
        { error: `Invalid status. Valid values: ${VALID_STATUSES.join(", ")}` },
        { status: 400 },
      );
    }
    status = rawStatus as CampaignStatus;
  }

  const where = status ? { status } : {};

  const [rows, total] = await Promise.all([
    db.campaign.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: {
        actors: {
          select: { confidence: true, actor: { select: { id: true, name: true } } },
          orderBy: { confidence: "desc" },
        },
        _count: { select: { indicators: true, techniques: true } },
      },
    }),
    db.campaign.count({ where }),
  ]);

  return NextResponse.json(
    {
      data: rows.map((c) => ({
        id:             c.id,
        name:           c.name,
        slug:           c.slug,
        description:    c.description,
        status:         c.status,
        startDate:      c.startDate?.toISOString() ?? null,
        endDate:        c.endDate?.toISOString() ?? null,
        targetSectors:  c.targetSectors,
        targetCountries: c.targetCountries,
        confidence:     c.confidence,
        tlp:            c.tlp,
        actors:         c.actors.map((a) => ({
          id:         a.actor.id,
          name:       a.actor.name,
          confidence: a.confidence,
        })),
        indicatorCount: c._count.indicators,
        techniqueCount: c._count.techniques,
        createdAt:      c.createdAt.toISOString(),
        updatedAt:      c.updatedAt.toISOString(),
      })),
      meta: {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
      },
    },
    { headers: auth.headers },
  );
}
