import {
  OPERATOR_LABELS,
  fieldDef,
  type Condition,
  type HuntQueryAst,
} from "@/lib/hunting/schema";

export type DetectionLanguage = "kql" | "spl" | "lucene";

export const DETECTION_LANGUAGES: readonly {
  id: DetectionLanguage;
  label: string;
}[] = [
  { id: "kql", label: "KQL" },
  { id: "spl", label: "SPL" },
  { id: "lucene", label: "Lucene" },
] as const;

const FIELD_NAMES: Record<string, string> = {
  type: "type",
  severity: "severity",
  tlp: "tlp",
  confidence: "confidence",
  value: "value",
  tag: "tags",
  source: "source",
  firstSeen: "firstSeen",
  lastSeen: "lastSeen",
};

function q(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function join(ast: HuntQueryAst, parts: string[]): string {
  return parts.join(ast.match === "any" ? " OR " : " AND ");
}

function scalar(condition: Condition): string {
  return Array.isArray(condition.value) ? condition.value[0] : condition.value;
}

function list(condition: Condition): string[] {
  return Array.isArray(condition.value) ? condition.value : [condition.value];
}

function kqlCondition(condition: Condition): string {
  const field = FIELD_NAMES[condition.field] ?? condition.field;
  const value = scalar(condition);

  switch (condition.op) {
    case "eq":
      return `${field} == ${q(value)}`;
    case "neq":
      return `${field} != ${q(value)}`;
    case "in":
      return `${field} in (${list(condition).map(q).join(", ")})`;
    case "contains":
    case "has":
      return `${field} has ${q(value)}`;
    case "gte":
      return `${field} >= ${Number(value)}`;
    case "lte":
      return `${field} <= ${Number(value)}`;
    case "after":
      return `${field} >= datetime(${value})`;
    case "before":
      return `${field} < datetime(${value})`;
  }
}

function splCondition(condition: Condition): string {
  const field = FIELD_NAMES[condition.field] ?? condition.field;
  const value = scalar(condition);

  switch (condition.op) {
    case "eq":
      return `${field}=${q(value)}`;
    case "neq":
      return `${field}!=${q(value)}`;
    case "in":
      return `(${list(condition)
        .map((v) => `${field}=${q(v)}`)
        .join(" OR ")})`;
    case "contains":
    case "has":
      return `${field}=*${value.replace(/\*/g, "\\*")}*`;
    case "gte":
      return `${field}>=${Number(value)}`;
    case "lte":
      return `${field}<=${Number(value)}`;
    case "after":
      return `${field}>=${q(value)}`;
    case "before":
      return `${field}<${q(value)}`;
  }
}

function luceneCondition(condition: Condition): string {
  const field = FIELD_NAMES[condition.field] ?? condition.field;
  const value = scalar(condition);

  switch (condition.op) {
    case "eq":
      return `${field}:${q(value)}`;
    case "neq":
      return `NOT ${field}:${q(value)}`;
    case "in":
      return `${field}:(${list(condition).map(q).join(" OR ")})`;
    case "contains":
    case "has":
      return `${field}:*${value.replace(/\*/g, "\\*")}*`;
    case "gte":
      return `${field}:[${Number(value)} TO *]`;
    case "lte":
      return `${field}:[* TO ${Number(value)}]`;
    case "after":
      return `${field}:[${value} TO *]`;
    case "before":
      return `${field}:[* TO ${value}]`;
  }
}

export function compileDetectionQuery(
  ast: HuntQueryAst,
  language: DetectionLanguage,
): string {
  const conditions = ast.conditions.filter((c) => fieldDef(c.field));
  if (conditions.length === 0) return "";

  if (language === "kql") {
    return [
      "PulseIndicators",
      "| where whitelisted == false",
      `| where ${join(ast, conditions.map(kqlCondition))}`,
    ].join("\n");
  }

  if (language === "spl") {
    return [
      'index=* sourcetype="pulse:indicator" whitelisted=false',
      `| search ${join(ast, conditions.map(splCondition))}`,
    ].join("\n");
  }

  return join(ast, conditions.map(luceneCondition));
}

export function explainDetectionQuery(ast: HuntQueryAst): string {
  const match = ast.match === "any" ? "OR" : "AND";
  const conditions = ast.conditions
    .map((c) => {
      const def = fieldDef(c.field);
      if (!def) return null;
      const value = Array.isArray(c.value) ? c.value.join(", ") : c.value;
      return `${def.label} ${OPERATOR_LABELS[c.op]} ${value}`;
    })
    .filter(Boolean);

  return conditions.join(` ${match} `);
}
