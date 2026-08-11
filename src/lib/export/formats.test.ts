import { describe, expect, it } from "vitest";
import {
  formatExport,
  stixPattern,
  toCsv,
  toMispEvent,
  toSnortRules,
  toStixBundle,
  type ExportIndicator,
} from "@/lib/export/formats";

function ind(overrides: Partial<ExportIndicator> = {}): ExportIndicator {
  const value = overrides.value ?? "1.2.3.4";
  return {
    type: "IPV4",
    value,
    // Mirror the real invariant: normalizedValue is the refanged, lowercased
    // form. Derive it from value unless a test sets it explicitly.
    normalizedValue: overrides.normalizedValue ?? value.toLowerCase(),
    confidence: 80,
    severity: "HIGH",
    tlp: "AMBER",
    tags: ["c2"],
    firstSeen: new Date("2026-01-01T00:00:00.000Z"),
    lastSeen: new Date("2026-02-01T00:00:00.000Z"),
    source: "abuse.ch",
    ...overrides,
  };
}

describe("toCsv", () => {
  it("emits a header and one row per indicator", () => {
    const csv = toCsv([ind(), ind({ value: "5.6.7.8" })]);
    const lines = csv.trimEnd().split("\r\n");
    expect(lines[0]).toBe(
      "type,value,confidence,severity,tlp,tags,source,firstSeen,lastSeen",
    );
    expect(lines).toHaveLength(3);
    expect(lines[1]).toContain("1.2.3.4");
  });

  it("quotes cells containing commas or quotes", () => {
    const csv = toCsv([ind({ source: "vendor, inc", tags: ['a"b'] })]);
    expect(csv).toContain('"vendor, inc"');
    expect(csv).toContain('"a""b"');
  });

  it("joins tags with a pipe so the comma stays the delimiter", () => {
    const csv = toCsv([ind({ tags: ["a", "b", "c"] })]);
    expect(csv).toContain("a|b|c");
  });

  it("neutralizes leading spreadsheet formula characters (CWE-1236)", () => {
    const csv = toCsv([
      ind({ value: '=HYPERLINK("http://evil.example")' }),
      ind({ value: "+cmd|' /C calc'!A0" }),
      ind({ value: "@SUM(1,2)" }),
      ind({ value: "-1+1" }),
      ind({ value: "1.2.3.4" }),
    ]);
    expect(csv).toContain("'=HYPERLINK");
    expect(csv).toContain("'+cmd|");
    expect(csv).toContain("'@SUM");
    expect(csv).toContain("'-1+1");
    expect(csv).toContain("1.2.3.4");
  });
});

describe("stixPattern", () => {
  it("maps common observable types", () => {
    expect(stixPattern(ind({ type: "IPV4", value: "1.2.3.4" }))).toBe(
      "[ipv4-addr:value = '1.2.3.4']",
    );
    expect(stixPattern(ind({ type: "DOMAIN", value: "evil.com" }))).toBe(
      "[domain-name:value = 'evil.com']",
    );
    expect(
      stixPattern(ind({ type: "SHA256", value: "abc" })),
    ).toBe("[file:hashes.'SHA-256' = 'abc']");
  });

  it("escapes single quotes in values", () => {
    expect(stixPattern(ind({ type: "URL", value: "http://a/'x" }))).toBe(
      "[url:value = 'http://a/\\'x']",
    );
  });

  it("strips the AS prefix for autonomous systems", () => {
    expect(stixPattern(ind({ type: "ASN", value: "AS64512" }))).toBe(
      "[autonomous-system:number = 64512]",
    );
  });

  it("returns null for types with no clean observable", () => {
    expect(stixPattern(ind({ type: "CVE", value: "CVE-2026-1" }))).toBeNull();
    expect(stixPattern(ind({ type: "BTC_ADDRESS", value: "1abc" }))).toBeNull();
  });
});

describe("toStixBundle", () => {
  it("produces a 2.1 bundle and omits unmappable indicators", () => {
    const bundle = JSON.parse(
      toStixBundle([
        ind({ type: "IPV4" }),
        ind({ type: "CVE", value: "CVE-2026-1" }), // omitted
      ]),
    );
    expect(bundle.type).toBe("bundle");
    expect(bundle.objects).toHaveLength(1);
    expect(bundle.objects[0]).toMatchObject({
      type: "indicator",
      spec_version: "2.1",
      pattern_type: "stix",
      confidence: 80,
    });
  });

  it("gives the same indicator a stable id across exports", () => {
    const a = JSON.parse(toStixBundle([ind()])).objects[0].id;
    const b = JSON.parse(toStixBundle([ind()])).objects[0].id;
    expect(a).toBe(b);
    expect(a).toMatch(/^indicator--[0-9a-f-]{36}$/);
  });
});

describe("toMispEvent", () => {
  it("maps types to MISP attribute types and sets to_ids by confidence", () => {
    const event = JSON.parse(
      toMispEvent([
        ind({ type: "SHA256", value: "abc", confidence: 90 }),
        ind({ type: "DOMAIN", value: "evil.com", confidence: 20 }),
      ]),
    );
    expect(event.Event.Attribute[0]).toMatchObject({
      type: "sha256",
      value: "abc",
      to_ids: true,
    });
    expect(event.Event.Attribute[1]).toMatchObject({
      type: "domain",
      to_ids: false,
    });
  });

  it("tags each attribute with its TLP", () => {
    const event = JSON.parse(toMispEvent([ind({ tlp: "AMBER_STRICT" })]));
    const tags = event.Event.Attribute[0].Tag.map((t: { name: string }) => t.name);
    expect(tags).toContain("tlp:amber-strict");
  });
});

describe("toSnortRules", () => {
  it("emits rules only for network observables", () => {
    const rules = toSnortRules([
      ind({ type: "IPV4", value: "1.2.3.4" }),
      ind({ type: "DOMAIN", value: "evil.com" }),
      ind({ type: "SHA256", value: "abc" }), // skipped
    ]);
    expect(rules).toContain("alert ip $HOME_NET any -> 1.2.3.4 any");
    expect(rules).toContain('dns.query; content:"evil.com"');
    expect(rules).toMatch(/1 non-network indicator/);
    expect(rules).toContain("#   SHA256 abc");
  });

  it("assigns unique, incrementing sids", () => {
    const rules = toSnortRules([
      ind({ type: "IPV4", value: "1.1.1.1" }),
      ind({ type: "IPV4", value: "2.2.2.2" }),
    ]);
    expect(rules).toContain("sid:3000000;");
    expect(rules).toContain("sid:3000001;");
  });

  it("uses the URL path for http content", () => {
    const rules = toSnortRules([
      ind({ type: "URL", value: "http://evil.com/malware.bin?x=1" }),
    ]);
    expect(rules).toContain('http.uri; content:"/malware.bin?x=1"');
  });
});

describe("formatExport dispatch", () => {
  it("routes each format id to its formatter", () => {
    const one = [ind()];
    expect(formatExport(one, "csv")).toBe(toCsv(one));
    expect(formatExport(one, "snort")).toBe(toSnortRules(one));
    expect(JSON.parse(formatExport(one, "stix")).type).toBe("bundle");
    expect(JSON.parse(formatExport(one, "misp")).Event).toBeDefined();
  });
});
