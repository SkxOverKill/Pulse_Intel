/**
 * GET /api/sigma/actor/:id
 *
 * Generates and streams a YAML bundle of Sigma detection rules derived from:
 *   - Network/hash/host indicators linked to the actor
 *   - ATT&CK techniques mapped to the actor
 *
 * Returns a downloadable .yml file. Compatible with sigma-cli, sigma-backend,
 * and every SIEM that accepts Sigma rules as input.
 *
 * Only indicators with confidence ≥ 50 and not whitelisted are included —
 * low-confidence IOCs in detection rules cause analyst fatigue fast.
 */

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getCurrentUser } from "@/lib/auth/dal";
import { generateSigmaRules, rulesToYamlBundle } from "@/lib/sigma/generate";

const NETWORK_TYPES = new Set(["IPV4", "IPV6", "DOMAIN", "URL"]);
const HASH_TYPES    = new Set(["MD5", "SHA1", "SHA256"]);
const HOST_TYPES    = new Set(["MUTEX", "FILENAME", "REGISTRY_KEY"]);
const MIN_CONFIDENCE = 50;

export async function GET(
  _req: Request,
  props: { params: Promise<{ id: string }> },
) {
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await props.params;

  const actor = await db.threatActor.findUnique({
    where: { id },
    select: {
      name: true,
      slug: true,
      attackGroupId: true,
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
    },
  });

  if (!actor) {
    return NextResponse.json({ error: "Actor not found" }, { status: 404 });
  }

  const allIndicators = actor.indicators.map((ai) => ai.indicator);

  const rules = generateSigmaRules({
    actorName:         actor.name,
    attackGroupId:     actor.attackGroupId,
    techniques:        actor.techniques.map((t) => ({
      attackId:   t.technique.attackId,
      name:       t.technique.name,
      confidence: t.confidence,
    })),
    networkIndicators: allIndicators.filter((i) => NETWORK_TYPES.has(i.type)),
    hashIndicators:    allIndicators.filter((i) => HASH_TYPES.has(i.type)),
    hostIndicators:    allIndicators.filter((i) => HOST_TYPES.has(i.type)),
  });

  const yaml     = rulesToYamlBundle(rules);
  const filename = `sigma-${actor.slug}-${new Date().toISOString().slice(0, 10)}.yml`;

  return new Response(yaml, {
    headers: {
      "Content-Type":        "text/yaml; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "X-Rule-Count":        String(rules.length),
    },
  });
}
