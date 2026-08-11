import { describe, expect, it } from "vitest";
import {
  HUNT_FIELDS,
  INDICATOR_TYPES,
  SEVERITIES,
  TLPS,
  describeHunt,
  validateHuntQuery,
  type HuntQueryAst,
} from "@/lib/hunting/schema";
import { compileWhere } from "@/lib/hunting/compile";

const ok = (q: unknown): HuntQueryAst => {
  const r = validateHuntQuery(q);
  if (!r.ok) throw new Error(`expected valid, got: ${r.errors.join("; ")}`);
  return r.ast;
};

const errs = (q: unknown): string[] => {
  const r = validateHuntQuery(q);
  if (r.ok) throw new Error("expected invalid");
  return r.errors;
};

describe("validateHuntQuery", () => {
  it("accepts a well-formed query and coerces defaults", () => {
    const ast = ok({
      entity: "indicator",
      conditions: [{ field: "type", op: "eq", value: "IPV4" }],
    });
    expect(ast.match).toBe("all"); // defaulted
    expect(ast.conditions).toHaveLength(1);
  });

  it("requires the indicator entity", () => {
    expect(errs({ entity: "actor", conditions: [] })).toContain(
      'Query entity must be "indicator".',
    );
  });

  it("rejects an empty condition list", () => {
    expect(errs({ entity: "indicator", conditions: [] })).toContain(
      "Add at least one condition.",
    );
  });

  it("rejects unknown fields", () => {
    const e = errs({
      entity: "indicator",
      conditions: [{ field: "nope", op: "eq", value: "x" }],
    });
    expect(e[0]).toMatch(/unknown field/);
  });

  it("rejects an operator the field does not support", () => {
    // `value` only supports contains, not eq.
    const e = errs({
      entity: "indicator",
      conditions: [{ field: "value", op: "eq", value: "evil.com" }],
    });
    expect(e[0]).toMatch(/does not support/);
  });

  it("rejects an invalid enum value", () => {
    const e = errs({
      entity: "indicator",
      conditions: [{ field: "type", op: "eq", value: "IPV9" }],
    });
    expect(e[0]).toMatch(/not a valid Type/);
  });

  it("rejects out-of-range confidence", () => {
    const e = errs({
      entity: "indicator",
      conditions: [{ field: "confidence", op: "gte", value: "150" }],
    });
    expect(e[0]).toMatch(/0–100/);
  });

  it("rejects a malformed date", () => {
    const e = errs({
      entity: "indicator",
      conditions: [{ field: "firstSeen", op: "after", value: "yesterday" }],
    });
    expect(e[0]).toMatch(/YYYY-MM-DD/);
  });

  it("requires at least one option for `in`", () => {
    const e = errs({
      entity: "indicator",
      conditions: [{ field: "type", op: "in", value: [] }],
    });
    expect(e[0]).toMatch(/at least one option/);
  });

  it("reports every bad condition at once", () => {
    const e = errs({
      entity: "indicator",
      conditions: [
        { field: "type", op: "eq", value: "BAD" },
        { field: "confidence", op: "gte", value: "999" },
      ],
    });
    expect(e).toHaveLength(2);
  });

  it("does not expose whitelisted as a huntable field", () => {
    const e = errs({
      entity: "indicator",
      conditions: [{ field: "whitelisted", op: "eq", value: "false" }],
    });
    expect(e[0]).toMatch(/unknown field/);
  });
});

describe("compileWhere", () => {
  it("always excludes whitelisted indicators", () => {
    const where = compileWhere(
      ok({
        entity: "indicator",
        conditions: [{ field: "type", op: "eq", value: "IPV4" }],
      }),
    );
    expect(where.AND).toBeDefined();
    const guard = (where.AND as unknown[])[0];
    expect(guard).toEqual({ whitelisted: false });
  });

  it("maps `all` to AND and `any` to OR", () => {
    const all = compileWhere(
      ok({
        entity: "indicator",
        match: "all",
        conditions: [
          { field: "type", op: "eq", value: "DOMAIN" },
          { field: "confidence", op: "gte", value: "80" },
        ],
      }),
    );
    const allInner = (all.AND as Record<string, unknown>[])[1];
    expect(allInner).toHaveProperty("AND");

    const any = compileWhere(
      ok({
        entity: "indicator",
        match: "any",
        conditions: [
          { field: "type", op: "eq", value: "DOMAIN" },
          { field: "type", op: "eq", value: "URL" },
        ],
      }),
    );
    const anyInner = (any.AND as Record<string, unknown>[])[1];
    expect(anyInner).toHaveProperty("OR");
  });

  it("lowercases the value needle to match the normalized column", () => {
    const where = compileWhere(
      ok({
        entity: "indicator",
        conditions: [{ field: "value", op: "contains", value: "Evil.COM" }],
      }),
    );
    const inner = (where.AND as Record<string, unknown>[])[1];
    const frag = (inner.AND as Record<string, unknown>[])[0];
    expect(frag).toEqual({ normalizedValue: { contains: "evil.com" } });
  });

  it("compiles `in` to a Prisma in-clause", () => {
    const where = compileWhere(
      ok({
        entity: "indicator",
        conditions: [{ field: "type", op: "in", value: ["IPV4", "IPV6"] }],
      }),
    );
    const inner = (where.AND as Record<string, unknown>[])[1];
    const frag = (inner.AND as Record<string, unknown>[])[0];
    expect(frag).toEqual({ type: { in: ["IPV4", "IPV6"] } });
  });

  it("treats `before` as start-of-day and `after` as next-day-start", () => {
    const where = compileWhere(
      ok({
        entity: "indicator",
        conditions: [{ field: "firstSeen", op: "after", value: "2026-01-01" }],
      }),
    );
    const inner = (where.AND as Record<string, unknown>[])[1];
    const frag = (inner.AND as { firstSeen: { gte: Date } }[])[0];
    expect(frag.firstSeen.gte.toISOString()).toBe("2026-01-02T00:00:00.000Z");
  });
});

describe("describeHunt", () => {
  it("renders a readable AND summary", () => {
    const s = describeHunt(
      ok({
        entity: "indicator",
        match: "all",
        conditions: [
          { field: "type", op: "eq", value: "IPV4" },
          { field: "confidence", op: "gte", value: "80" },
        ],
      }),
    );
    expect(s).toBe("Type is IPV4 AND Confidence ≥ 80");
  });

  it("joins with OR for any-match", () => {
    const s = describeHunt(
      ok({
        entity: "indicator",
        match: "any",
        conditions: [
          { field: "tag", op: "has", value: "ransomware" },
          { field: "tag", op: "has", value: "c2" },
        ],
      }),
    );
    expect(s).toBe("Tag includes ransomware OR Tag includes c2");
  });
});

describe("field catalogue", () => {
  it("enum option lists stay in sync with the Prisma enums", () => {
    // A cheap guard: if someone adds an IndicatorType and forgets the catalogue,
    // this count mismatch flags it before it ships as an un-huntable value.
    expect(INDICATOR_TYPES).toHaveLength(15);
    expect(SEVERITIES).toHaveLength(5);
    expect(TLPS).toHaveLength(5);
  });

  it("every field declares at least one operator", () => {
    for (const f of HUNT_FIELDS) expect(f.ops.length).toBeGreaterThan(0);
  });
});
