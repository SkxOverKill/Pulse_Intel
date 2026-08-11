import type { HuntQueryAst } from "@/lib/hunting/schema";

export type HuntTemplate = {
  id: string;
  name: string;
  description: string;
  ast: HuntQueryAst;
};

export const HUNT_TEMPLATES: readonly HuntTemplate[] = [
  {
    id: "high-confidence-network-iocs",
    name: "High-confidence network IOCs",
    description: "Domains, URLs, IPv4, and IPv6 indicators with confidence at or above 80.",
    ast: {
      entity: "indicator",
      match: "all",
      conditions: [
        { field: "type", op: "in", value: ["DOMAIN", "URL", "IPV4", "IPV6"] },
        { field: "confidence", op: "gte", value: "80" },
      ],
    },
  },
  {
    id: "critical-cves",
    name: "Critical CVEs",
    description: "Critical vulnerability indicators for patch and exposure review.",
    ast: {
      entity: "indicator",
      match: "all",
      conditions: [
        { field: "type", op: "eq", value: "CVE" },
        { field: "severity", op: "eq", value: "CRITICAL" },
      ],
    },
  },
  {
    id: "ransomware-tagged",
    name: "Ransomware tagged IOCs",
    description: "Indicators tagged as ransomware, extortion, or leak-site related.",
    ast: {
      entity: "indicator",
      match: "any",
      conditions: [
        { field: "tag", op: "has", value: "ransomware" },
        { field: "tag", op: "has", value: "extortion" },
        { field: "tag", op: "has", value: "leak-site" },
      ],
    },
  },
  {
    id: "recent-high-severity",
    name: "Recent high-severity indicators",
    description: "High or critical indicators observed after a chosen date.",
    ast: {
      entity: "indicator",
      match: "all",
      conditions: [
        { field: "severity", op: "in", value: ["HIGH", "CRITICAL"] },
        { field: "lastSeen", op: "after", value: "2026-08-01" },
      ],
    },
  },
] as const;

export function huntTemplateById(id: string): HuntTemplate | undefined {
  return HUNT_TEMPLATES.find((template) => template.id === id);
}
