/**
 * GET /api/sigma/campaign/:id
 *
 * Sigma rule bundle for a campaign — same approach as the actor endpoint but
 * pulls indicators and techniques from campaign join tables.
 */

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getCurrentUser } from "@/lib/auth/dal";
import { generateSigmaRules, rulesToYamlBundle } from "@/lib/sigma/generate";

const NETWORK_TYPES  = new Set(["IPV4", "IPV6", "DOMAIN", "URL"]);
const HASH_TYPES     = new Set(["MD5", "SHA1", "SHA256"]);
const HOST_TYPES     = new Set(["MUTEX", "FILENAME", "REGISTRY_KEY"]);
const MIN_CONFIDENCE = 50;

export async function GET(
  _req: Request,
  props: { params: Promise<{ id: string }> },
) {
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await props.params;

  const campaign = await db.campaign.findUnique({
    where: { id },
    select: {
      name: true,
      slug: true,
      techniques: {
        include: {
          technique: { select: { attackId: true, name: true } },
        },
      },
      indicators: {
        where: {
          indicator: { whitelisted: false, confidence: { gte: MIN_CONFIDENCE } },
        },
        include: {
          indicator: { select: { type: true, normalizedValue: true, confidence: true } },
        },
      },
      // Pull actor group IDs for tagging — use the first linked actor's ATT&CK ID if present.
      actors: {
        include: { actor: { select: { attackGroupId: true } } },
        take: 1,
      },
    },
  });

  if (!campaign) {
    return NextResponse.json({ error: "Campaign not found" }, { status: 404 });
  }

  const attackGroupId = campaign.actors[0]?.actor.attackGroupId ?? null;
  const allIndicators = campaign.indicators.map((ci) => ci.indicator);

  const rules = generateSigmaRules({
    actorName:         campaign.name,
    attackGroupId,
    techniques:        campaign.techniques.map((t) => ({
      attackId:   t.technique.attackId,
      name:       t.technique.name,
      confidence: t.confidence,
    })),
    networkIndicators: allIndicators.filter((i) => NETWORK_TYPES.has(i.type)),
    hashIndicators:    allIndicators.filter((i) => HASH_TYPES.has(i.type)),
    hostIndicators:    allIndicators.filter((i) => HOST_TYPES.has(i.type)),
  });

  const yaml     = rulesToYamlBundle(rules);
  const filename = `sigma-${campaign.slug}-${new Date().toISOString().slice(0, 10)}.yml`;

  return new Response(yaml, {
    headers: {
      "Content-Type":        "text/yaml; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "X-Rule-Count":        String(rules.length),
    },
  });
}
