/**
 * GET /api/v1/indicators/:id/context
 *
 * 360° context pivot for a single indicator.
 *
 * This is the endpoint SOAR playbooks call when they need everything the
 * platform knows about an IOC in one shot — enrichment verdicts, attribution,
 * related reports, active campaigns. Without this they'd need 4-5 separate
 * calls and a join in the playbook itself.
 *
 * Response shape is stable and additive-only. New fields will be added but
 * existing fields will not be renamed or removed without a major version bump.
 *
 * Authentication: Bearer API key (same as all /api/v1/* routes).
 * Scope required: none (any valid key can read context).
 *
 * Example:
 *   curl -H "Authorization: Bearer pi_..." \
 *        https://your-pulse.example.com/api/v1/indicators/clxyz.../context
 */

import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { requireApiKey } from "@/lib/api/auth";
import { defang } from "@/lib/ioc/normalize";

export async function GET(
  req: NextRequest,
  props: { params: Promise<{ id: string }> },
) {
  const auth = await requireApiKey(req);
  if (!auth.ok) return auth.response;

  const { id } = await props.params;

  const indicator = await db.indicator.findUnique({
    where: { id },
    include: {
      source:      { select: { name: true, type: true } },
      enrichments: {
        orderBy: { fetchedAt: "desc" },
        select: {
          provider:    true,
          verdict:     true,
          score:       true,
          fetchedAt:   true,
          expiresAt:   true,
          error:       true,
          rawResponse: true,
        },
      },
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
        },
        orderBy: { confidence: "desc" },
      },
      campaigns: {
        include: {
          campaign: {
            select: {
              id:     true,
              name:   true,
              slug:   true,
              status: true,
            },
          },
        },
        orderBy: { confidence: "desc" },
      },
      reports: {
        include: {
          report: {
            select: {
              id:          true,
              title:       true,
              slug:        true,
              publishedAt: true,
              tlp:         true,
              tags:        true,
            },
          },
        },
        orderBy: { confidence: "desc" },
        take: 10,
      },
    },
  });

  if (!indicator) {
    return NextResponse.json({ error: "Indicator not found" }, { status: 404 });
  }

  // Whitelisted indicators are fully readable via context (the whitelist is
  // an export/alerting control, not an access control) but we surface the
  // flag so callers can decide how to handle them.

  // Compute aggregate verdict: max score wins (see enrich.ts rationale).
  const scores = indicator.enrichments
    .filter((e) => !e.error && e.score !== null)
    .map((e) => e.score as number);
  const maxScore = scores.length > 0 ? Math.max(...scores) : null;

  const aggregateVerdict =
    maxScore === null ? "UNKNOWN" :
    maxScore >= 70    ? "MALICIOUS" :
    maxScore >= 30    ? "SUSPICIOUS" : "BENIGN";

  // Fresh = at least one enrichment is still within its TTL.
  const now = new Date();
  const enrichmentFresh = indicator.enrichments.some((e) => e.expiresAt > now);

  const body = {
    // Core fields
    id:               indicator.id,
    type:             indicator.type,
    value:            indicator.value,
    defanged:         defang(indicator.value),
    normalizedValue:  indicator.normalizedValue,
    whitelisted:      indicator.whitelisted,

    // Temporal metadata
    firstSeen:        indicator.firstSeen.toISOString(),
    lastSeen:         indicator.lastSeen.toISOString(),
    expiresAt:        indicator.expiresAt?.toISOString() ?? null,

    // Classification
    severity:         indicator.severity,
    confidence:       indicator.confidence,
    tlp:              indicator.tlp,
    tags:             indicator.tags,

    // Source provenance
    source: indicator.source
      ? { name: indicator.source.name, type: indicator.source.type }
      : null,

    // Aggregate enrichment
    enrichmentSummary: {
      verdict:     aggregateVerdict,
      maxScore,
      providerCount: indicator.enrichments.length,
      fresh:         enrichmentFresh,
    },

    // Per-provider enrichment
    enrichments: indicator.enrichments.map((e) => ({
      provider:  e.provider,
      verdict:   e.verdict,
      score:     e.score,
      fresh:     e.expiresAt > now,
      fetchedAt: e.fetchedAt.toISOString(),
      expiresAt: e.expiresAt.toISOString(),
      error:     e.error ?? null,
      // raw is included — callers wanting GreyNoise classification or Shodan
      // ports need it, and they're authenticated anyway.
      raw:       e.rawResponse,
    })),

    // Attribution
    actors: indicator.actors.map((a) => ({
      id:            a.actor.id,
      name:          a.actor.name,
      slug:          a.actor.slug,
      attackGroupId: a.actor.attackGroupId,
      country:       a.actor.country,
      motivation:    a.actor.motivation,
      active:        a.actor.active,
      confidence:    a.confidence,
    })),

    campaigns: indicator.campaigns.map((c) => ({
      id:         c.campaign.id,
      name:       c.campaign.name,
      slug:       c.campaign.slug,
      status:     c.campaign.status,
      confidence: c.confidence,
    })),

    // Related reports (newest first, capped at 10)
    reports: indicator.reports.map((r) => ({
      id:          r.report.id,
      title:       r.report.title,
      slug:        r.report.slug,
      publishedAt: r.report.publishedAt?.toISOString() ?? null,
      tlp:         r.report.tlp,
      tags:        r.report.tags,
      confidence:  r.confidence,
    })),
  };

  return NextResponse.json(body, {
    headers: {
      ...auth.headers,
      "Cache-Control": "private, max-age=60",
    },
  });
}
