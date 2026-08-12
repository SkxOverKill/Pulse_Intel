import { describe, it, expect } from "vitest";
import {
  exportHeader,
  exportBatch,
  exportFooter,
  createExportState,
  formatExport,
  type ExportFormat,
  type ExportIndicator,
} from "./formats";

function ind(over: Partial<ExportIndicator>): ExportIndicator {
  return {
    type: "IPV4",
    value: "1.2.3.4",
    normalizedValue: "1.2.3.4",
    confidence: 80,
    severity: "HIGH",
    tlp: "AMBER",
    tags: ["botnet"],
    firstSeen: new Date("2024-01-01T00:00:00Z"),
    lastSeen: new Date("2024-01-02T00:00:00Z"),
    expiresAt: null,
    source: "feedA",
    ...over,
  } as ExportIndicator;
}

/** Mirror of the route's streaming assembly, so the test covers what ships. */
function assemble(batches: ExportIndicator[][], format: ExportFormat, cap: number): string {
  const state = createExportState();
  let out = exportHeader(format, cap);
  for (const b of batches) {
    const s = exportBatch(b, format, state);
    if (s) out += s;
  }
  out += exportFooter(format, state);
  return out;
}

/** Byte-encoded stream, exactly like the route body (Response requires bytes). */
async function assembleViaStream(
  batches: ExportIndicator[][],
  format: ExportFormat,
  cap: number,
): Promise<string> {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const state = createExportState();
      controller.enqueue(encoder.encode(exportHeader(format, cap)));
      for (const b of batches) {
        const s = exportBatch(b, format, state);
        if (s) controller.enqueue(encoder.encode(s));
      }
      controller.enqueue(encoder.encode(exportFooter(format, state)));
      controller.close();
    },
  });
  return new Response(stream, { headers: { "Content-Type": "text/plain" } }).text();
}

describe("streamed export — byte encoding (Response body must yield bytes)", () => {
  it("reads back cleanly for every format", async () => {
    const rows = [ind({ type: "IPV4", value: "8.8.8.8", normalizedValue: "8.8.8.8" })];
    for (const fmt of ["csv", "stix", "misp", "snort", "zeek"] as ExportFormat[]) {
      const text = await assembleViaStream([rows], fmt, 1);
      expect(text.length).toBeGreaterThan(0);
    }
  });
});

describe("streamed STIX/MISP produce valid JSON", () => {
  it("empty first batch (all non-observable) then a real batch still parses", () => {
    const cve = [ind({ type: "CVE", value: "CVE-2024-0001", normalizedValue: "cve-2024-0001" })];
    const ip = [ind({ type: "IPV4", value: "8.8.8.8", normalizedValue: "8.8.8.8" })];
    const doc = assemble([cve, ip], "stix", 2);
    const parsed = JSON.parse(doc);
    expect(parsed.type).toBe("bundle");
    expect(parsed.objects).toHaveLength(1);
  });

  it("multi-batch STIX parses with the right object count", () => {
    const doc = assemble(
      [
        [ind({ type: "IPV4" }), ind({ type: "DOMAIN", value: "a.test", normalizedValue: "a.test" })],
        [ind({ type: "URL", value: "http://b.test/x", normalizedValue: "http://b.test/x" })],
      ],
      "stix",
      3,
    );
    expect(JSON.parse(doc).objects).toHaveLength(3);
  });

  it("all-non-observable STIX yields a valid empty bundle", () => {
    const doc = assemble([[ind({ type: "CVE", value: "CVE-2024-9999" })]], "stix", 1);
    expect(JSON.parse(doc).objects).toHaveLength(0);
  });

  it("multi-batch MISP parses", () => {
    const doc = assemble(
      [[ind({ type: "IPV4" })], [ind({ type: "DOMAIN", value: "c.test", normalizedValue: "c.test" })]],
      "misp",
      2,
    );
    expect(JSON.parse(doc).Event.Attribute).toHaveLength(2);
  });
});

describe("streamed snort is deterministic and honest", () => {
  it("repeat exports of identical input are byte-identical (SID does not leak)", () => {
    const rows = [
      ind({ type: "IPV4", value: "9.9.9.9", normalizedValue: "9.9.9.9" }),
      ind({ type: "DOMAIN", value: "evil.test", normalizedValue: "evil.test" }),
    ];
    expect(assemble([rows], "snort", 2)).toBe(assemble([rows], "snort", 2));
  });

  it("SIDs start at the private base each export", () => {
    const rows = [ind({ type: "IPV4", value: "9.9.9.9", normalizedValue: "9.9.9.9" })];
    expect(assemble([rows], "snort", 1)).toContain("sid:3000000;");
  });

  it("lists non-network indicators that were skipped", () => {
    const rows = [
      ind({ type: "IPV4", value: "9.9.9.9", normalizedValue: "9.9.9.9" }),
      ind({ type: "CVE", value: "CVE-2024-0001" }),
    ];
    const doc = assemble([rows], "snort", 2);
    expect(doc).toContain("not expressible as rules");
    expect(doc).toContain("#   CVE CVE-2024-0001");
  });
});

describe("streamed CSV/Zeek match the non-streaming exporter", () => {
  it("CSV output equals formatExport", () => {
    const rows = [ind({ type: "IPV4" }), ind({ type: "DOMAIN", value: "d.test", normalizedValue: "d.test" })];
    expect(assemble([rows], "csv", 2)).toBe(formatExport(rows, "csv"));
  });

  it("Zeek output equals formatExport", () => {
    const rows = [ind({ type: "IPV4" }), ind({ type: "MD5", value: "d41d8cd98f00b204e9800998ecf8427e", normalizedValue: "d41d8cd98f00b204e9800998ecf8427e" })];
    expect(assemble([rows], "zeek", 2)).toBe(formatExport(rows, "zeek"));
  });
});
