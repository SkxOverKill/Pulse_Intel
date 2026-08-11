import { NextResponse } from "next/server";
import type { AttackDomain } from "@/generated/prisma/enums";
import { db } from "@/lib/db";
import { getCurrentUser } from "@/lib/auth/dal";
import { buildNavigatorLayer } from "@/lib/attack/matrix";

const DOMAINS: AttackDomain[] = ["ENTERPRISE", "MOBILE", "ICS"];

/**
 * ATT&CK Navigator layer export.
 *
 * proxy.ts deliberately skips /api, so this route authenticates itself rather
 * than assuming a gate upstream.
 */
export async function GET(request: Request) {
  const user = await getCurrentUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const url = new URL(request.url);
  const domainParam = url.searchParams.get("domain") ?? "ENTERPRISE";
  const actorId = url.searchParams.get("actorId") ?? undefined;

  if (!DOMAINS.includes(domainParam as AttackDomain)) {
    return NextResponse.json({ error: "Unknown domain" }, { status: 400 });
  }
  const domain = domainParam as AttackDomain;

  let name = `Pulse Intelligence — ${domain.toLowerCase()} coverage`;
  let description =
    "Techniques mapped to tracked threat actors, scored by how many actors use each.";

  if (actorId) {
    const actor = await db.threatActor.findUnique({
      where: { id: actorId },
      select: { name: true },
    });
    if (!actor) {
      return NextResponse.json({ error: "Actor not found" }, { status: 404 });
    }
    name = `Pulse Intelligence — ${actor.name}`;
    description = `ATT&CK techniques mapped to ${actor.name}.`;
  }

  const layer = await buildNavigatorLayer({ domain, actorId, name, description });

  const filename = `pulse-${actorId ? "actor" : domain.toLowerCase()}-layer.json`;

  return new NextResponse(JSON.stringify(layer, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
