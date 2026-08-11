import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";

const PAGE_SIZE_DEFAULT = 50;
const PAGE_SIZE_MAX = 200;

/** GET /api/v1/actors — the public, programmatic equivalent of /actors. */
export async function GET(req: NextRequest) {
  const auth = await requireApiKey(req, "actors:read");
  if (!auth.ok) return auth.response;

  const params = req.nextUrl.searchParams;
  const page = Math.max(1, Number(params.get("page")) || 1);
  const pageSize = Math.min(
    PAGE_SIZE_MAX,
    Math.max(1, Number(params.get("pageSize")) || PAGE_SIZE_DEFAULT),
  );
  const active = params.get("active");

  const where = active !== null ? { active: active === "true" } : {};

  const [rows, total] = await Promise.all([
    db.threatActor.findMany({
      where,
      orderBy: { name: "asc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: { aliases: { select: { alias: true, namedBy: true } } },
    }),
    db.threatActor.count({ where }),
  ]);

  return NextResponse.json({
    data: rows.map((a) => ({
      id: a.id,
      name: a.name,
      slug: a.slug,
      attackGroupId: a.attackGroupId,
      country: a.country,
      motivation: a.motivation,
      sophistication: a.sophistication,
      active: a.active,
      confidence: a.confidence,
      tlp: a.tlp,
      aliases: a.aliases,
      firstSeen: a.firstSeen,
      lastSeen: a.lastSeen,
    })),
    page,
    pageSize,
    total,
  });
}
