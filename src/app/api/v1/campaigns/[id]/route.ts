import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";

/**
 * GET /api/v1/campaigns/:id
 *
 * Full campaign record including linked actors, techniques, and indicator count.
 * Indicators themselves are paginated — use GET /api/v1/indicators?campaignId=:id
 * (coming) for the full set.
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireApiKey(req, "actors:read");
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const campaign = await db.campaign.findUnique({
    where: { id },
    include: {
      actors: {
        include: {
          actor: {
            select: {
              id:            true,
              name:          true,
              slug:          true,
              attackGroupId: true,
              country:       true,
              motivation:    true,
              active:        true,
            },
          },
          addedBy: { select: { name: true } },
        },
        orderBy: { confidence: "desc" },
      },
      techniques: {
        include: {
          technique: { select: { attackId: true, name: true, tactics: true } },
        },
        orderBy: { confidence: "desc" },
      },
      _count: { select: { indicators: true } },
    },
  });

  if (!campaign) {
    return NextResponse.json(
      { error: "Campaign not found." },
      { status: 404, headers: auth.headers },
    );
  }

  return NextResponse.json(
    {
      data: {
        id:              campaign.id,
        name:            campaign.name,
        slug:            campaign.slug,
        description:     campaign.description,
        status:          campaign.status,
        startDate:       campaign.startDate?.toISOString() ?? null,
        endDate:         campaign.endDate?.toISOString() ?? null,
        targetSectors:   campaign.targetSectors,
        targetCountries: campaign.targetCountries,
        confidence:      campaign.confidence,
        tlp:             campaign.tlp,
        actors: campaign.actors.map((a) => ({
          id:            a.actor.id,
          name:          a.actor.name,
          slug:          a.actor.slug,
          attackGroupId: a.actor.attackGroupId,
          country:       a.actor.country,
          motivation:    a.actor.motivation,
          active:        a.actor.active,
          confidence:    a.confidence,
          attributedBy:  a.addedBy?.name ?? null,
        })),
        techniques: campaign.techniques.map((t) => ({
          attackId:   t.technique.attackId,
          name:       t.technique.name,
          tactics:    t.technique.tactics,
          confidence: t.confidence,
        })),
        indicatorCount: campaign._count.indicators,
        createdAt:      campaign.createdAt.toISOString(),
        updatedAt:      campaign.updatedAt.toISOString(),
      },
    },
    { headers: auth.headers },
  );
}
