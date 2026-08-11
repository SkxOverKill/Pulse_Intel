import { describe, expect, it } from "vitest";
import {
  generateSigmaRules,
  ruleToYaml,
  type GenerateOptions,
} from "@/lib/sigma/generate";

function opts(overrides: Partial<GenerateOptions> = {}): GenerateOptions {
  return {
    actorName: "Fancy Bear",
    techniques: [],
    networkIndicators: [],
    hashIndicators: [],
    hostIndicators: [],
    ...overrides,
  };
}

describe("generateSigmaRules", () => {
  it("does not generate a network rule with no network indicators", () => {
    const rules = generateSigmaRules(opts());
    expect(rules).toHaveLength(0);
  });

  it("splits network types into named sub-selections so `1 of selection*` ORs them", () => {
    const rules = generateSigmaRules(
      opts({
        networkIndicators: [
          { type: "DOMAIN", normalizedValue: "evil.example.com", confidence: 90 },
          { type: "IPV4", normalizedValue: "203.0.113.7", confidence: 90 },
        ],
      }),
    );

    const net = rules.find((r) => r.title.includes("Network IOC"));
    expect(net).toBeDefined();
    expect(net!.detection.condition).toBe("1 of selection*");
    // A flat `selection` map ANDs its fields; named sub-selections are what
    // makes the condition a true OR across DNS/IP/URL.
    expect(Object.keys(net!.detection.selection).sort()).toEqual([
      "selection_dns",
      "selection_ip",
    ]);
    expect(net!.detection.selection.selection_dns).toEqual({
      "dns.question.name|contains": ["evil.example.com"],
    });
  });

  it("uses the Sysmon Hashes field for all three hash types", () => {
    const rules = generateSigmaRules(
      opts({
        hashIndicators: [
          { type: "SHA256", normalizedValue: "a".repeat(64), confidence: 90 },
          { type: "MD5", normalizedValue: "b".repeat(32), confidence: 90 },
        ],
      }),
    );

    const hash = rules.find((r) => r.title.includes("File Hash"));
    expect(hash).toBeDefined();
    expect(Object.keys(hash!.detection.selection).sort()).toEqual([
      "selection_md5",
      "selection_sha256",
    ]);
    expect(hash!.detection.selection.selection_sha256).toEqual({
      "Hashes|contains": [`SHA256=${"A".repeat(64)}`],
    });
    expect(hash!.detection.selection.selection_md5).toEqual({
      "Hashes|contains": [`MD5=${"B".repeat(32)}`],
    });
  });

  it("emits per-type sub-selections for host artifacts", () => {
    const rules = generateSigmaRules(
      opts({
        hostIndicators: [
          { type: "MUTEX", normalizedValue: "\\BaseNamedObjects\\evil", confidence: 90 },
          { type: "REGISTRY_KEY", normalizedValue: "HKCU\\Software\\Evil", confidence: 90 },
        ],
      }),
    );

    const host = rules.find((r) => r.title.includes("Host Artifact"));
    expect(host).toBeDefined();
    expect(Object.keys(host!.detection.selection).sort()).toEqual([
      "selection_mutex",
      "selection_regkey",
    ]);
  });

  it("serializes sub-selections into valid YAML", () => {
    const rules = generateSigmaRules(
      opts({
        networkIndicators: [
          { type: "DOMAIN", normalizedValue: "evil.example.com", confidence: 90 },
          { type: "IPV4", normalizedValue: "203.0.113.7", confidence: 90 },
        ],
      }),
    );

    const yaml = ruleToYaml(rules[0]);
    expect(yaml).toContain("selection_dns:");
    expect(yaml).toContain("selection_ip:");
    expect(yaml).toContain("1 of selection*");
    expect(yaml).toContain("- evil.example.com");
  });
});
