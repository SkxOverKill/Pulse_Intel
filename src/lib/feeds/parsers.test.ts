import { describe, expect, it } from "vitest";
import { parseCsv, parseEpss, parseKev, parseNvd, parseRss } from "./parsers";

describe("parseRss", () => {
  it("parses RSS 2.0 items", () => {
    const xml = `<rss><channel>
      <item>
        <title>Critical flaw exploited</title>
        <link>https://example.com/post-1</link>
        <pubDate>Tue, 15 Jul 2026 10:00:00 GMT</pubDate>
        <description>A short summary.</description>
      </item>
    </channel></rss>`;
    const items = parseRss(xml);
    expect(items).toHaveLength(1);
    expect(items[0].title).toBe("Critical flaw exploited");
    expect(items[0].url).toBe("https://example.com/post-1");
    expect(items[0].publishedAt.getUTCFullYear()).toBe(2026);
  });

  it("parses Atom entries with href links", () => {
    const xml = `<feed>
      <entry>
        <title>Atom post</title>
        <link rel="alternate" href="https://example.com/atom-1"/>
        <published>2026-07-01T08:30:00Z</published>
        <summary>Atom summary.</summary>
      </entry>
    </feed>`;
    const items = parseRss(xml);
    expect(items).toHaveLength(1);
    expect(items[0].url).toBe("https://example.com/atom-1");
    expect(items[0].summary).toBe("Atom summary.");
  });

  it("unwraps CDATA and decodes entities", () => {
    const xml = `<rss><item>
      <title><![CDATA[Ransomware & extortion]]></title>
      <link>https://example.com/a?x=1&amp;y=2</link>
      <description>&lt;p&gt;HTML summary&lt;/p&gt;</description>
    </item></rss>`;
    const items = parseRss(xml);
    expect(items[0].title).toBe("Ransomware & extortion");
    expect(items[0].url).toBe("https://example.com/a?x=1&y=2");
    // HTML inside the summary is stripped, not rendered.
    expect(items[0].summary).toBe("HTML summary");
  });

  it("skips items with no usable link", () => {
    const xml = `<rss><item><title>No link</title></item></rss>`;
    expect(parseRss(xml)).toHaveLength(0);
  });

  it("skips non-http links rather than storing javascript: URLs", () => {
    const xml = `<rss><item><title>Bad</title><link>javascript:alert(1)</link></item></rss>`;
    expect(parseRss(xml)).toHaveLength(0);
  });

  it("falls back to now for an unparseable date", () => {
    const xml = `<rss><item><title>T</title><link>https://e.com/1</link><pubDate>not a date</pubDate></item></rss>`;
    const items = parseRss(xml);
    expect(items[0].publishedAt.getTime()).toBeGreaterThan(Date.now() - 10_000);
  });

  it("returns nothing for empty or junk input", () => {
    expect(parseRss("")).toEqual([]);
    expect(parseRss("<html><body>not a feed</body></html>")).toEqual([]);
  });
});

describe("parseCsv", () => {
  it("parses a simple table", () => {
    const rows = parseCsv("a,b\n1,2\n3,4");
    expect(rows).toEqual([
      { a: "1", b: "2" },
      { a: "3", b: "4" },
    ]);
  });

  it("skips comment preamble lines", () => {
    // abuse.ch and EPSS both ship these.
    const rows = parseCsv("# generated 2026-07-21\n# vendor notes\nid,value\n1,x");
    expect(rows).toEqual([{ id: "1", value: "x" }]);
  });

  it("handles quoted fields containing commas", () => {
    const rows = parseCsv('a,b\n"one, two",three');
    expect(rows[0].a).toBe("one, two");
    expect(rows[0].b).toBe("three");
  });

  it("handles doubled quotes inside a quoted field", () => {
    const rows = parseCsv('a\n"say ""hi"""');
    expect(rows[0].a).toBe('say "hi"');
  });

  it("handles newlines inside quoted fields", () => {
    const rows = parseCsv('a,b\n"line1\nline2",x');
    expect(rows[0].a).toBe("line1\nline2");
    expect(rows[0].b).toBe("x");
  });

  it("returns nothing when there is no data row", () => {
    expect(parseCsv("a,b")).toEqual([]);
    expect(parseCsv("")).toEqual([]);
  });

  it("strips a UTF-8 BOM so the first header cell still matches", () => {
    const rows = parseCsv("\uFEFFurl,status\nhttps://evil.example,online");
    expect(rows[0]).toEqual({ url: "https://evil.example", status: "online" });
  });
});

describe("parseKev", () => {
  it("flags every entry as known-exploited", () => {
    const out = parseKev({
      vulnerabilities: [
        {
          cveID: "CVE-2024-3400",
          shortDescription: "Command injection",
          dateAdded: "2024-04-12",
        },
      ],
    });
    expect(out).toHaveLength(1);
    expect(out[0].cveId).toBe("CVE-2024-3400");
    expect(out[0].knownExploited).toBe(true);
    expect(out[0].kevDateAdded?.getUTCFullYear()).toBe(2024);
  });

  it("tolerates a missing vulnerabilities array", () => {
    expect(parseKev({})).toEqual([]);
  });
});

describe("parseEpss", () => {
  it("parses scores and skips the model preamble", () => {
    const csv = "#model_version:v2026\ncve,epss,percentile\nCVE-2024-3400,0.97,0.99\nCVE-2021-44228,0.94,0.98";
    const out = parseEpss(csv);
    expect(out).toHaveLength(2);
    expect(out[0]).toEqual({ cveId: "CVE-2024-3400", epssScore: 0.97 });
  });

  it("drops malformed rows rather than storing NaN", () => {
    const csv = "cve,epss\nNOTACVE,0.5\nCVE-2024-1,notanumber\nCVE-2024-2,0.3";
    const out = parseEpss(csv);
    expect(out).toEqual([{ cveId: "CVE-2024-2", epssScore: 0.3 }]);
  });
});

describe("parseNvd", () => {
  it("prefers the English description and CVSS v3.1", () => {
    const out = parseNvd({
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2026-1234",
            published: "2026-01-15T00:00:00.000",
            descriptions: [
              { lang: "es", value: "spanish" },
              { lang: "en", value: "english text" },
            ],
            metrics: {
              cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }],
              cvssMetricV40: [{ cvssData: { baseScore: 9.3 } }],
            },
            references: [{ url: "https://vendor.example/advisory" }],
          },
        },
      ],
    });
    expect(out[0].cveId).toBe("CVE-2026-1234");
    expect(out[0].description).toBe("english text");
    expect(out[0].cvssV3).toBe(9.8);
    expect(out[0].cvssV4).toBe(9.3);
    expect(out[0].vendorRefs).toEqual(["https://vendor.example/advisory"]);
  });

  it("falls back to v3.0 when v3.1 is absent", () => {
    const out = parseNvd({
      vulnerabilities: [
        { cve: { id: "CVE-2026-2", metrics: { cvssMetricV30: [{ cvssData: { baseScore: 7.5 } }] } } },
      ],
    });
    expect(out[0].cvssV3).toBe(7.5);
  });

  it("handles entries with no metrics at all", () => {
    const out = parseNvd({ vulnerabilities: [{ cve: { id: "CVE-2026-3" } }] });
    expect(out[0].cvssV3).toBeNull();
    expect(out[0].cvssV4).toBeNull();
  });
});
