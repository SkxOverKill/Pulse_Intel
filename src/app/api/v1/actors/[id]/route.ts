import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";

/** GET /api/v1/actors/:id — profile plus linked techniques, malware, tools. */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireApiKey(req, "actors:read");
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const actor = await db.threatActor.findUnique({
    where: { id },
    include: {
      aliases: { select: { alias: true, namedBy: true } },
      techniques: {
        select: {
          confidence: true,
          technique: { select: { attackId: true, name: true } },
        },
      },
      malware: {
        select: { confidence: true, malware: { select: { name: true } } },
      },
      tools: { select: { confidence: true, tool: { select: { name: true } } } },
    },
  });

  if (!actor) {
    return NextResponse.json(
      { error: "Actor not found." },
      { status: 404, headers: auth.headers },
    );
  }

  return NextResponse.json(
    {
      data: {
        id: actor.id,
        name: actor.name,
        slug: actor.slug,
        description: actor.description,
        attackGroupId: actor.attackGroupId,
        country: actor.country,
        motivation: actor.motivation,
        sophistication: actor.sophistication,
        active: actor.active,
        confidence: actor.confidence,
        tlp: actor.tlp,
        targetSectors: actor.targetSectors,
        targetCountries: actor.targetCountries,
        aliases: actor.aliases,
        // Every relation carries its own confidence — attribution is opinion,
        // not fact (design rule 1) — so the API surfaces it, not just the name.
        techniques: actor.techniques.map((t) => ({
          attackId: t.technique.attackId,
          name: t.technique.name,
          confidence: t.confidence,
        })),
        malware: actor.malware.map((m) => ({
          name: m.malware.name,
          confidence: m.confidence,
        })),
        tools: actor.tools.map((t) => ({
          name: t.tool.name,
          confidence: t.confidence,
        })),
        firstSeen: actor.firstSeen,
        lastSeen: actor.lastSeen,
      },
    },
    { headers: auth.headers },
  );
}
