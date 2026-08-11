/**
 * Compiles a validated HuntQueryAst into a Prisma `where` for the Indicator
 * table. Kept separate from schema.ts so the client builder never pulls in the
 * Prisma types transitively — this file is server/worker only, but carries no
 * `server-only` marker because the worker imports it outside a bundler.
 *
 * Two invariants live here, not in the caller:
 *   1. Whitelisted indicators are never matched. Design rule 3 — a whitelisted
 *      IOC is stored so you can see a feed claimed it, but is never exported,
 *      enriched, or alerted on. A hunt is an alert source, so it must obey this
 *      regardless of what the AST says.
 *   2. An empty condition list matches nothing, not everything. A saved hunt
 *      should never silently alert on the entire table; validation already
 *      rejects zero conditions, and this is the belt to that suspenders.
 */
import type { Prisma } from "@/generated/prisma/client";
import type {
  IndicatorType,
  Severity,
  Tlp,
} from "@/generated/prisma/enums";
import type { Condition, HuntQueryAst } from "@/lib/hunting/schema";

export function compileWhere(ast: HuntQueryAst): Prisma.IndicatorWhereInput {
  const fragments = ast.conditions.map(compileCondition);

  // Never match nothing-into-everything: no fragments ⇒ an impossible clause.
  const combined: Prisma.IndicatorWhereInput =
    fragments.length === 0
      ? { id: { equals: "" } }
      : ast.match === "any"
        ? { OR: fragments }
        : { AND: fragments };

  return { AND: [{ whitelisted: false }, combined] };
}

function compileCondition(c: Condition): Prisma.IndicatorWhereInput {
  const arr = Array.isArray(c.value) ? c.value : [c.value];
  const str = Array.isArray(c.value) ? c.value[0] : c.value;

  switch (c.field) {
    case "type":
      return enumWhere("type", c.op, str, arr as IndicatorType[]);
    case "severity":
      return enumWhere("severity", c.op, str, arr as Severity[]);
    case "tlp":
      return enumWhere("tlp", c.op, str, arr as Tlp[]);

    case "confidence": {
      const n = Number(str);
      if (c.op === "gte") return { confidence: { gte: n } };
      if (c.op === "lte") return { confidence: { lte: n } };
      return { confidence: n };
    }

    case "value":
      // Match the normalized column: it is refanged and lowercased, so the
      // needle must be too or "Evil.COM" would never find "evil.com".
      return { normalizedValue: { contains: str.toLowerCase() } };

    case "tag":
      return { tags: { has: str } };

    case "source":
      return c.op === "neq" ? { sourceId: { not: str } } : { sourceId: str };

    case "attackTechnique": {
      const needle =
        c.op === "contains"
          ? { contains: str, mode: "insensitive" as const }
          : { equals: str, mode: "insensitive" as const };
      return {
        OR: [
          {
            actors: {
              some: {
                actor: {
                  techniques: {
                    some: {
                      technique: { OR: [{ attackId: needle }, { name: needle }] },
                    },
                  },
                },
              },
            },
          },
          {
            campaigns: {
              some: {
                campaign: {
                  techniques: {
                    some: {
                      technique: { OR: [{ attackId: needle }, { name: needle }] },
                    },
                  },
                },
              },
            },
          },
        ],
      };
    }

    case "attackTactic":
      return {
        OR: [
          {
            actors: {
              some: {
                actor: {
                  techniques: { some: { technique: { tactics: { has: str } } } },
                },
              },
            },
          },
          {
            campaigns: {
              some: {
                campaign: {
                  techniques: { some: { technique: { tactics: { has: str } } } },
                },
              },
            },
          },
        ],
      };

    case "firstSeen":
    case "lastSeen": {
      // A bare YYYY-MM-DD is midnight UTC; "before 2026-01-01" should include
      // all of the 31st, so "before" compares against the given day's start and
      // "after" against the next day's start.
      const start = new Date(`${str}T00:00:00.000Z`);
      if (c.op === "before") return { [c.field]: { lt: start } };
      const next = new Date(start.getTime() + 24 * 3600 * 1000);
      return { [c.field]: { gte: next } };
    }

    default:
      // Unreachable for a validated AST; a compiled impossible clause is the
      // safe failure if an unknown field ever slips through.
      return { id: { equals: "" } };
  }
}

function enumWhere<T extends string>(
  column: "type" | "severity" | "tlp",
  op: Condition["op"],
  scalar: string,
  list: T[],
): Prisma.IndicatorWhereInput {
  if (op === "in") return { [column]: { in: list } };
  if (op === "neq") return { [column]: { not: scalar } };
  return { [column]: scalar };
}
