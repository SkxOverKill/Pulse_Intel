/**
 * /actors/compare?a=<id>&b=<id>
 *
 * Side-by-side threat actor comparison — technique overlap, shared targeting,
 * common infrastructure. When two actors keep showing up in the same incidents
 * and someone asks "are these the same group?", this page is the answer.
 *
 * Overlap scoring (0-100):
 *   - Technique Jaccard similarity × 50 pts
 *   - Target sector overlap × 20 pts
 *   - Target country overlap × 20 pts
 *   - Same origin country × 10 pts
 * Scores ≥ 60 = "high overlap, consider merging records"
 * Scores 30-60 = "possible relationship"
 * Scores < 30 = "likely distinct actors"
 */

import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { db } from "@/lib/db";
import { getCurrentUser } from "@/lib/auth/dal";
import { Card, CardHeader, ConfidenceBar } from "@/components/ui/primitives";
import { Muted, PageHeader, Tag } from "@/components/ui/page";

export const metadata = { title: "Actor comparison · Pulse Intelligence" };

function jaccard(setA: Set<string>, setB: Set<string>): number {
  if (setA.size === 0 && setB.size === 0) return 0;
  let intersection = 0;
  for (const x of setA) if (setB.has(x)) intersection++;
  const union = setA.size + setB.size - intersection;
  return union > 0 ? intersection / union : 0;
}

function overlapScore(
  a: { techniques: string[]; sectors: string[]; countries: string[]; country: string | null },
  b: { techniques: string[]; sectors: string[]; countries: string[]; country: string | null },
): { total: number; breakdown: { label: string; score: number; max: number }[] } {
  const techJ = jaccard(new Set(a.techniques), new Set(b.techniques));
  const sectorJ = jaccard(new Set(a.sectors), new Set(b.sectors));
  const countryJ = jaccard(new Set(a.countries), new Set(b.countries));
  const sameOrigin = a.country && b.country && a.country === b.country ? 1 : 0;

  const techScore = Math.round(techJ * 50);
  const sectorScore = Math.round(sectorJ * 20);
  const countryScore = Math.round(countryJ * 20);
  const originScore = sameOrigin * 10;

  return {
    total: Math.min(100, techScore + sectorScore + countryScore + originScore),
    breakdown: [
      { label: "Technique overlap", score: techScore, max: 50 },
      { label: "Target sector overlap", score: sectorScore, max: 20 },
      { label: "Target country overlap", score: countryScore, max: 20 },
      { label: "Same origin country", score: originScore, max: 10 },
    ],
  };
}

function overlapTone(score: number): { text: string; bg: string; label: string } {
  if (score >= 60) return { text: "text-sev-critical", bg: "bg-sev-critical/10", label: "High overlap — consider merging records" };
  if (score >= 30) return { text: "text-warn", bg: "bg-warn/10", label: "Possible relationship" };
  return { text: "text-ink-muted", bg: "bg-surface-2", label: "Likely distinct actors" };
}

type Actor = Awaited<ReturnType<typeof fetchActor>>;

async function fetchActor(id: string) {
  return db.threatActor.findUnique({
    where: { id },
    include: {
      techniques: { include: { technique: { select: { attackId: true, name: true, tactics: true } } } },
      aliases: { select: { alias: true, namedBy: true } },
      _count: { select: { indicators: true } },
    },
  });
}


function ActorColumn({ actor }: { actor: NonNullable<Actor> }) {
  return (
    <div className="space-y-4">
      <div>
        <Link href={`/actors/${actor.id}`} className="text-sm font-semibold text-ink hover:text-brand">
          {actor.name}
        </Link>
        {actor.attackGroupId ? (
          <p className="mt-0.5 font-mono text-[11px] text-ink-faint">{actor.attackGroupId}</p>
        ) : null}
      </div>
      <dl className="space-y-1.5 text-xs">
        <div className="flex items-center justify-between gap-2">
          <span className="text-ink-faint">Status</span>
          <span className={actor.active ? "text-ok" : "text-ink-muted"}>
            {actor.active ? "Active" : "Inactive"}
          </span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-ink-faint">Origin</span>
          <span>{actor.country ?? <Muted>Unknown</Muted>}</span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-ink-faint">Motivation</span>
          <span>{actor.motivation.replace("_", " ").toLowerCase()}</span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-ink-faint">Indicators</span>
          <span className="tabular">{actor._count.indicators}</span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-ink-faint">Confidence</span>
          <ConfidenceBar value={actor.confidence} />
        </div>
      </dl>
      <div>
        <p className="mb-1 text-xs text-ink-faint">Aliases</p>
        <div className="flex flex-wrap gap-1">
          {actor.aliases.length > 0
            ? actor.aliases.map((a) => (
                <Tag key={a.alias} title={a.namedBy ?? undefined}>{a.alias}</Tag>
              ))
            : <Muted>None recorded</Muted>}
        </div>
      </div>
      <div>
        <p className="mb-1 text-xs text-ink-faint">Target sectors</p>
        <div className="flex flex-wrap gap-1">
          {actor.targetSectors.length > 0
            ? actor.targetSectors.map((s) => <Tag key={s}>{s}</Tag>)
            : <Muted>None recorded</Muted>}
        </div>
      </div>
    </div>
  );
}

export default async function ActorComparePage(props: {
  searchParams: Promise<{ a?: string; b?: string }>;
}) {
  await getCurrentUser();
  const params = await props.searchParams;

  if (!params.a || !params.b) {
    redirect("/actors");
  }

  const [actorA, actorB] = await Promise.all([
    fetchActor(params.a),
    fetchActor(params.b),
  ]);

  if (!actorA || !actorB) notFound();

  const techA = new Set(actorA.techniques.map((t) => t.technique.attackId));
  const techB = new Set(actorB.techniques.map((t) => t.technique.attackId));

  const sharedTechniques = actorA.techniques
    .filter((t) => techB.has(t.technique.attackId))
    .map((t) => t.technique);

  const onlyA = actorA.techniques
    .filter((t) => !techB.has(t.technique.attackId))
    .map((t) => t.technique);

  const onlyB = actorB.techniques
    .filter((t) => !techA.has(t.technique.attackId))
    .map((t) => t.technique);

  const sharedSectors = actorA.targetSectors.filter((s) =>
    actorB.targetSectors.includes(s),
  );

  const score = overlapScore(
    { techniques: [...techA], sectors: actorA.targetSectors, countries: actorA.targetCountries, country: actorA.country },
    { techniques: [...techB], sectors: actorB.targetSectors, countries: actorB.targetCountries, country: actorB.country },
  );

  const tone = overlapTone(score.total);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Actor comparison"
        description="Technique overlap, shared targeting, and similarity scoring between two threat actors."
      />

      {/* Similarity score hero */}
      <div className={`mb-4 rounded-[--radius-card] border p-4 ${tone.bg} border-line`}>
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <p className="text-xs text-ink-faint">Similarity score</p>
            <p className={`tabular text-4xl font-bold ${tone.text}`}>{score.total}</p>
            <p className="mt-0.5 text-xs text-ink-muted">{tone.label}</p>
          </div>
          <div className="flex flex-1 flex-wrap gap-3">
            {score.breakdown.map((b) => (
              <div key={b.label} className="min-w-32">
                <p className="text-[10px] text-ink-faint">{b.label}</p>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-3">
                  <div
                    className={`h-full rounded-full ${tone.text.replace("text-", "bg-")}`}
                    style={{ width: `${(b.score / b.max) * 100}%` }}
                  />
                </div>
                <p className="tabular mt-0.5 text-[10px] text-ink-muted">
                  {b.score}/{b.max}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Actor profiles side by side */}
      <div className="mb-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={actorA.name} />
          <div className="px-4 py-4">
            <ActorColumn actor={actorA} />
          </div>
        </Card>
        <Card>
          <CardHeader title={actorB.name} />
          <div className="px-4 py-4">
            <ActorColumn actor={actorB} />
          </div>
        </Card>
      </div>

      {/* Shared sectors */}
      {sharedSectors.length > 0 ? (
        <Card className="mb-4">
          <CardHeader
            title="Shared target sectors"
            hint={`${sharedSectors.length} sector(s) both actors have been observed targeting`}
          />
          <div className="flex flex-wrap gap-2 px-4 py-4">
            {sharedSectors.map((s) => (
              <Tag key={s}>{s}</Tag>
            ))}
          </div>
        </Card>
      ) : null}

      {/* Technique comparison */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader
            title="Shared techniques"
            hint={`${sharedTechniques.length} technique(s) used by both actors`}
          />
          {sharedTechniques.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-ink-faint">No overlap</div>
          ) : (
            <ul className="divide-y divide-line/60">
              {sharedTechniques.map((t) => (
                <li key={t.attackId} className="px-4 py-2.5">
                  <Link
                    href={`/attack/${t.attackId}`}
                    className="text-sm font-medium text-ink hover:text-brand"
                  >
                    {t.attackId}
                  </Link>
                  <p className="text-xs text-ink-muted">{t.name}</p>
                  <p className="text-[10px] text-ink-faint">{t.tactics.join(", ")}</p>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader
            title={`Only ${actorA.name}`}
            hint={`${onlyA.length} technique(s) unique to this actor`}
          />
          {onlyA.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-ink-faint">No exclusive techniques</div>
          ) : (
            <ul className="divide-y divide-line/60">
              {onlyA.map((t) => (
                <li key={t.attackId} className="px-4 py-2.5">
                  <Link
                    href={`/attack/${t.attackId}`}
                    className="text-sm font-medium text-ink hover:text-brand"
                  >
                    {t.attackId}
                  </Link>
                  <p className="text-xs text-ink-muted">{t.name}</p>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader
            title={`Only ${actorB.name}`}
            hint={`${onlyB.length} technique(s) unique to this actor`}
          />
          {onlyB.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-ink-faint">No exclusive techniques</div>
          ) : (
            <ul className="divide-y divide-line/60">
              {onlyB.map((t) => (
                <li key={t.attackId} className="px-4 py-2.5">
                  <Link
                    href={`/attack/${t.attackId}`}
                    className="text-sm font-medium text-ink hover:text-brand"
                  >
                    {t.attackId}
                  </Link>
                  <p className="text-xs text-ink-muted">{t.name}</p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <p className="mt-4 text-xs text-ink-faint">
        <Link href="/actors" className="hover:text-ink">
          ← All actors
        </Link>
      </p>
    </div>
  );
}
