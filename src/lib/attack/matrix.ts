import { db } from "@/lib/db";
import type { AttackDomain } from "@/generated/prisma/enums";

/**
 * Builds the matrix: tactic columns, each holding its top-level techniques with
 * sub-techniques nested underneath, plus per-technique coverage counts.
 *
 * "Coverage" here means how many *tracked actors* are mapped to a technique.
 * That is the number worth surfacing on a matrix: it turns ATT&CK from a
 * reference poster into a view of what your adversaries actually do.
 */

export type MatrixTechnique = {
  id: string;
  attackId: string;
  name: string;
  deprecated: boolean;
  actorCount: number;
  subtechniques: MatrixTechnique[];
};

export type MatrixColumn = {
  shortname: string;
  name: string;
  attackId: string;
  techniques: MatrixTechnique[];
};

export async function getMatrix(domain: AttackDomain): Promise<{
  columns: MatrixColumn[];
  totalTechniques: number;
  coveredTechniques: number;
  attackVersion: string | null;
}> {
  const [tactics, techniques, coverage] = await Promise.all([
    db.tactic.findMany({
      where: { domain },
      orderBy: { order: "asc" },
    }),
    db.technique.findMany({
      where: { domain, deprecated: false },
      orderBy: { attackId: "asc" },
      select: {
        id: true,
        attackId: true,
        name: true,
        tactics: true,
        deprecated: true,
        isSubtechnique: true,
        parentId: true,
        attackVersion: true,
      },
    }),
    // Actor ids, not counts: a parent's coverage is the number of *distinct*
    // actors across it and its sub-techniques. Summing child counts would
    // double-count an actor mapped to several sub-techniques and can report
    // more actors than exist.
    db.actorTechnique.findMany({ select: { techniqueId: true, actorId: true } }),
  ]);

  const actorsByTechnique = new Map<string, Set<string>>();
  for (const row of coverage) {
    const set = actorsByTechnique.get(row.techniqueId) ?? new Set<string>();
    set.add(row.actorId);
    actorsByTechnique.set(row.techniqueId, set);
  }

  const countByTechnique = new Map(
    [...actorsByTechnique].map(([id, set]) => [id, set.size]),
  );

  const subsByParent = new Map<string, MatrixTechnique[]>();
  for (const t of techniques) {
    if (!t.isSubtechnique || !t.parentId) continue;
    const list = subsByParent.get(t.parentId) ?? [];
    list.push({
      id: t.id,
      attackId: t.attackId,
      name: t.name,
      deprecated: t.deprecated,
      actorCount: countByTechnique.get(t.id) ?? 0,
      subtechniques: [],
    });
    subsByParent.set(t.parentId, list);
  }

  const columns: MatrixColumn[] = tactics.map((tactic) => {
    const cells = techniques
      .filter((t) => !t.isSubtechnique && t.tactics.includes(tactic.shortname))
      .map((t) => {
        const subs = subsByParent.get(t.id) ?? [];
        // A parent counts as covered if it or any child is used, otherwise a
        // matrix of parents looks empty while the sub-techniques are mapped.
        // Union of actor ids, so an actor mapped to three sub-techniques
        // counts once.
        const actors = new Set(actorsByTechnique.get(t.id) ?? []);
        for (const sub of subs) {
          for (const actorId of actorsByTechnique.get(sub.id) ?? []) {
            actors.add(actorId);
          }
        }
        return {
          id: t.id,
          attackId: t.attackId,
          name: t.name,
          deprecated: t.deprecated,
          actorCount: actors.size,
          subtechniques: subs,
        };
      });

    return {
      shortname: tactic.shortname,
      name: tactic.name,
      attackId: tactic.attackId,
      techniques: cells,
    };
  });

  const covered = techniques.filter(
    (t) => (countByTechnique.get(t.id) ?? 0) > 0,
  ).length;

  return {
    columns,
    totalTechniques: techniques.length,
    coveredTechniques: covered,
    attackVersion: techniques[0]?.attackVersion ?? null,
  };
}

/**
 * ATT&CK Navigator layer (v4.5 schema). Lets an analyst take Pulse's coverage
 * into Navigator, or into any tool that reads layer files.
 */
export async function buildNavigatorLayer(opts: {
  domain: AttackDomain;
  actorId?: string;
  name: string;
  description: string;
}) {
  const where = opts.actorId
    ? { actorId: opts.actorId, technique: { domain: opts.domain } }
    : { technique: { domain: opts.domain } };

  const mappings = await db.actorTechnique.findMany({
    where,
    include: { technique: { select: { attackId: true } } },
  });

  // Multiple actors can map the same technique; score by how many.
  const scores = new Map<string, number>();
  for (const m of mappings) {
    const id = m.technique.attackId;
    scores.set(id, (scores.get(id) ?? 0) + 1);
  }

  const domainKey =
    opts.domain === "ENTERPRISE"
      ? "enterprise-attack"
      : opts.domain === "MOBILE"
        ? "mobile-attack"
        : "ics-attack";

  const max = Math.max(1, ...scores.values());

  return {
    name: opts.name,
    versions: { attack: "19", navigator: "5.1.0", layer: "4.5" },
    domain: domainKey,
    description: opts.description,
    techniques: [...scores.entries()].map(([techniqueID, score]) => ({
      techniqueID,
      score,
      enabled: true,
    })),
    gradient: {
      colors: ["#0d1626", "#3b82f6", "#f43f5e"],
      minValue: 0,
      maxValue: max,
    },
    legendItems: [],
    showTacticRowBackground: true,
    tacticRowBackground: "#131f33",
    sorting: 0,
    hideDisabled: false,
  };
}
