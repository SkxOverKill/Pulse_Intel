/**
 * Hunt query model — the structured AST an analyst builds and the engine runs.
 *
 * This module is deliberately dependency-free: no `db`, no Prisma runtime, no
 * `server-only`. It is imported by the client-side query builder (for the field
 * catalogue and live validation), by the server actions (to validate before
 * persisting), and by the worker (which has no bundler). Keep it that way — the
 * moment it imports the Prisma client, the builder stops compiling.
 *
 * A hunt targets Indicators. That is the entity whose "new match since last run"
 * event is worth alerting on — a fresh IOC landing in a feed is the classic hunt
 * trigger. The AST names its entity so this can grow later without a rewrite.
 */

import type {
  IndicatorType,
  Severity,
  Tlp,
} from "@/generated/prisma/enums";

// Kept in sync with the Prisma enums by hand. A test asserts these cover the
// schema so a new enum value can't silently become un-huntable.
export const INDICATOR_TYPES = [
  "IPV4",
  "IPV6",
  "DOMAIN",
  "URL",
  "MD5",
  "SHA1",
  "SHA256",
  "EMAIL",
  "CVE",
  "BTC_ADDRESS",
  "REGISTRY_KEY",
  "MUTEX",
  "FILENAME",
  "USER_AGENT",
  "ASN",
] as const satisfies readonly IndicatorType[];

export const SEVERITIES = [
  "INFO",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
] as const satisfies readonly Severity[];

export const TLPS = [
  "CLEAR",
  "GREEN",
  "AMBER",
  "AMBER_STRICT",
  "RED",
] as const satisfies readonly Tlp[];

export type Operator =
  | "eq"
  | "neq"
  | "in"
  | "contains"
  | "gte"
  | "lte"
  | "before"
  | "after"
  | "has";

export const OPERATOR_LABELS: Record<Operator, string> = {
  eq: "is",
  neq: "is not",
  in: "is any of",
  contains: "contains",
  gte: "≥",
  lte: "≤",
  before: "before",
  after: "after",
  has: "includes",
};

export type FieldType = "enum" | "text" | "number" | "date" | "tag" | "source";

export type FieldDef = {
  key: string;
  label: string;
  type: FieldType;
  ops: readonly Operator[];
  options?: readonly string[];
  hint?: string;
};

/**
 * The single source of truth for what is huntable. The builder renders from it,
 * the validator checks against it, and the compiler maps each key to a column.
 *
 * `whitelisted` is deliberately absent and can never be added: whitelisted IOCs
 * are never alerted on (design rule 3), and the compiler enforces that no matter
 * what an AST asks for. Exposing it as a field would invite queries that look
 * like they work but silently return nothing.
 */
export const HUNT_FIELDS: readonly FieldDef[] = [
  {
    key: "type",
    label: "Type",
    type: "enum",
    ops: ["eq", "neq", "in"],
    options: INDICATOR_TYPES,
  },
  {
    key: "severity",
    label: "Severity",
    type: "enum",
    ops: ["eq", "neq", "in"],
    options: SEVERITIES,
  },
  {
    key: "tlp",
    label: "TLP",
    type: "enum",
    ops: ["eq", "neq", "in"],
    options: TLPS,
  },
  {
    key: "confidence",
    label: "Confidence",
    type: "number",
    ops: ["gte", "lte", "eq"],
    hint: "0–100",
  },
  {
    key: "value",
    label: "Value",
    type: "text",
    ops: ["contains"],
    hint: "matches the normalized (refanged, lowercased) value",
  },
  {
    key: "tag",
    label: "Tag",
    type: "tag",
    ops: ["has"],
  },
  {
    key: "source",
    label: "Source",
    type: "source",
    ops: ["eq", "neq"],
  },
  {
    key: "firstSeen",
    label: "First seen",
    type: "date",
    ops: ["after", "before"],
  },
  {
    key: "lastSeen",
    label: "Last seen",
    type: "date",
    ops: ["after", "before"],
  },
] as const;

export function fieldDef(key: string): FieldDef | undefined {
  return HUNT_FIELDS.find((f) => f.key === key);
}

/** A single predicate. `value` is a string for scalars, string[] for `in`. */
export type Condition = {
  field: string;
  op: Operator;
  value: string | string[];
};

export type HuntMatch = "all" | "any";

export type HuntQueryAst = {
  entity: "indicator";
  /** How the conditions combine: all = AND, any = OR. */
  match: HuntMatch;
  conditions: Condition[];
};

export type ValidationResult =
  | { ok: true; ast: HuntQueryAst }
  | { ok: false; errors: string[] };

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Validates and normalizes an untrusted query object into a HuntQueryAst.
 *
 * `query` is user-authored JSON persisted in the DB, so nothing here may assume
 * shape. Returns coerced values (numbers as numbers-in-strings stay strings for
 * transport; the compiler coerces) and a flat list of human-readable errors so
 * the form can show them all at once rather than one reload at a time.
 */
export function validateHuntQuery(query: unknown): ValidationResult {
  const errors: string[] = [];

  if (typeof query !== "object" || query === null) {
    return { ok: false, errors: ["Query must be an object."] };
  }
  const q = query as Record<string, unknown>;

  const entity = q.entity;
  if (entity !== "indicator") {
    errors.push('Query entity must be "indicator".');
  }

  const match: HuntMatch = q.match === "any" ? "any" : "all";

  const rawConditions = Array.isArray(q.conditions) ? q.conditions : [];
  if (rawConditions.length === 0) {
    errors.push("Add at least one condition.");
  }

  const conditions: Condition[] = [];
  rawConditions.forEach((raw, i) => {
    const label = `Condition ${i + 1}`;
    if (typeof raw !== "object" || raw === null) {
      errors.push(`${label}: malformed.`);
      return;
    }
    const c = raw as Record<string, unknown>;
    const def = fieldDef(String(c.field));
    if (!def) {
      errors.push(`${label}: unknown field "${String(c.field)}".`);
      return;
    }
    const op = c.op as Operator;
    if (!def.ops.includes(op)) {
      errors.push(
        `${label}: ${def.label} does not support "${OPERATOR_LABELS[op] ?? op}".`,
      );
      return;
    }

    const valueError = validateValue(def, op, c.value);
    if (valueError) {
      errors.push(`${label}: ${valueError}`);
      return;
    }

    conditions.push({
      field: def.key,
      op,
      value: normalizeValue(def, op, c.value),
    });
  });

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, ast: { entity: "indicator", match, conditions } };
}

function validateValue(
  def: FieldDef,
  op: Operator,
  value: unknown,
): string | null {
  if (op === "in") {
    const arr = Array.isArray(value) ? value : [];
    if (arr.length === 0) return "select at least one option.";
    for (const v of arr) {
      if (!def.options?.includes(String(v))) {
        return `"${String(v)}" is not a valid ${def.label}.`;
      }
    }
    return null;
  }

  const v = typeof value === "string" ? value.trim() : value;

  switch (def.type) {
    case "enum":
      if (!def.options?.includes(String(v))) {
        return `"${String(v)}" is not a valid ${def.label}.`;
      }
      return null;
    case "number": {
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0 || n > 100) {
        return "confidence must be a whole number 0–100.";
      }
      return null;
    }
    case "date":
      if (typeof v !== "string" || !ISO_DATE.test(v) || Number.isNaN(Date.parse(v))) {
        return "must be a date (YYYY-MM-DD).";
      }
      return null;
    case "text":
    case "tag":
    case "source":
      if (typeof v !== "string" || v.length === 0) {
        return "must not be empty.";
      }
      return null;
  }
}

function normalizeValue(
  def: FieldDef,
  op: Operator,
  value: unknown,
): string | string[] {
  if (op === "in") {
    return (Array.isArray(value) ? value : []).map(String);
  }
  return typeof value === "string" ? value.trim() : String(value);
}

/** Human-readable one-line summary of a validated AST, for lists and audit. */
export function describeHunt(ast: HuntQueryAst): string {
  if (ast.conditions.length === 0) return "All indicators";
  const joiner = ast.match === "all" ? " AND " : " OR ";
  const parts = ast.conditions.map((c) => {
    const def = fieldDef(c.field);
    const label = def?.label ?? c.field;
    const opLabel = OPERATOR_LABELS[c.op];
    const value = Array.isArray(c.value) ? c.value.join(", ") : c.value;
    return `${label} ${opLabel} ${value}`;
  });
  return parts.join(joiner);
}
