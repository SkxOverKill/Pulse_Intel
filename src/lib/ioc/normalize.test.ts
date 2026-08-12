import { describe, expect, it } from "vitest";
import {
  defang,
  detectType,
  normalize,
  parseBulk,
  parseIndicator,
  refang,
} from "./normalize";

describe("refang", () => {
  it("restores bracketed dots", () => {
    expect(refang("evil[.]com")).toBe("evil.com");
    expect(refang("evil(.)com")).toBe("evil.com");
    expect(refang("evil{.}com")).toBe("evil.com");
  });

  it("restores hxxp schemes", () => {
    expect(refang("hxxp://evil.com")).toBe("http://evil.com");
    expect(refang("hxxps://evil.com")).toBe("https://evil.com");
    expect(refang("hXXps://evil.com")).toBe("https://evil.com");
  });

  it("restores [dot] and [at] words", () => {
    expect(refang("evil[dot]com")).toBe("evil.com");
    expect(refang("bob[at]evil.com")).toBe("bob@evil.com");
  });

  it("handles whitespace inside brackets", () => {
    expect(refang("evil [ . ] com")).toBe("evil.com");
  });

  it("handles a fully defanged URL", () => {
    expect(refang("hxxps://bad[.]example[.]com/a/b")).toBe(
      "https://bad.example.com/a/b",
    );
  });

  it("leaves clean input untouched", () => {
    expect(refang("https://example.com/path")).toBe("https://example.com/path");
  });
});

describe("detectType", () => {
  it.each([
    ["8.8.8.8", "IPV4"],
    ["192.168.1.1", "IPV4"],
    ["evil.com", "DOMAIN"],
    ["sub.evil.co.uk", "DOMAIN"],
    ["https://evil.com/x", "URL"],
    ["bob@evil.com", "EMAIL"],
    ["CVE-2024-3400", "CVE"],
    ["cve-2021-44228", "CVE"],
    ["AS13335", "ASN"],
    ["d41d8cd98f00b204e9800998ecf8427e", "MD5"],
    ["da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1"],
    [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "SHA256",
    ],
    ["2001:db8::1", "IPV6"],
    ["HKLM\\Software\\Microsoft\\Run", "REGISTRY_KEY"],
  ])("detects %s as %s", (input, expected) => {
    expect(detectType(input)).toBe(expected);
  });

  it("detects defanged input by refanging first", () => {
    expect(detectType("evil[.]com")).toBe("DOMAIN");
    expect(detectType("hxxps://evil[.]com/x")).toBe("URL");
    expect(detectType("8[.]8[.]8[.]8")).toBe("IPV4");
  });

  it("rejects invalid IPv4 octets rather than calling them domains", () => {
    expect(detectType("999.1.1.1")).toBeNull();
    expect(detectType("256.1.1.1")).toBeNull();
  });

  it("returns null for unclassifiable input", () => {
    expect(detectType("")).toBeNull();
    expect(detectType("just some prose")).toBeNull();
    expect(detectType("abc123")).toBeNull();
  });

  it("does not mistake a hash for a domain", () => {
    expect(detectType("d41d8cd98f00b204e9800998ecf8427e")).toBe("MD5");
  });
});

describe("normalize", () => {
  it("lowercases hashes", () => {
    expect(normalize("D41D8CD98F00B204E9800998ECF8427E", "MD5")).toBe(
      "d41d8cd98f00b204e9800998ecf8427e",
    );
  });

  it("uppercases CVE ids", () => {
    expect(normalize("cve-2024-3400", "CVE")).toBe("CVE-2024-3400");
  });

  it("lowercases domains and strips the root dot", () => {
    expect(normalize("EVIL.COM.", "DOMAIN")).toBe("evil.com");
  });

  it("collapses a bare trailing slash on URLs", () => {
    expect(normalize("http://evil.com/", "URL")).toBe("http://evil.com");
    expect(normalize("http://evil.com", "URL")).toBe("http://evil.com");
  });

  it("drops URL fragments, which never reach the server", () => {
    expect(normalize("https://evil.com/a#frag", "URL")).toBe(
      "https://evil.com/a",
    );
  });

  it("preserves URL query strings, which do reach the server", () => {
    expect(normalize("https://evil.com/a?id=1", "URL")).toBe(
      "https://evil.com/a?id=1",
    );
  });

  it("preserves Bitcoin address case (base58 is case-sensitive)", () => {
    const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    expect(normalize(addr, "BTC_ADDRESS")).toBe(addr);
  });

  it("is idempotent", () => {
    const cases: [string, Parameters<typeof normalize>[1]][] = [
      ["EVIL.COM.", "DOMAIN"],
      ["http://evil.com/", "URL"],
      ["cve-2024-3400", "CVE"],
      ["D41D8CD98F00B204E9800998ECF8427E", "MD5"],
      ["Bob@Evil.COM", "EMAIL"],
    ];
    for (const [input, type] of cases) {
      const once = normalize(input, type);
      expect(normalize(once, type)).toBe(once);
    }
  });
});

describe("parseIndicator", () => {
  it("returns value, normalized value and type together", () => {
    expect(parseIndicator("hxxps://EVIL[.]com/")).toEqual({
      value: "https://EVIL.com/",
      normalizedValue: "https://evil.com",
      type: "URL",
    });
  });

  it("returns null for junk", () => {
    expect(parseIndicator("not an ioc")).toBeNull();
  });
});

describe("parseBulk", () => {
  it("parses one indicator per line", () => {
    const result = parseBulk("8.8.8.8\nevil.com\nCVE-2024-3400");
    expect(result.parsed).toHaveLength(3);
    expect(result.unparsed).toHaveLength(0);
  });

  it("collapses duplicates that differ only by defanging or case", () => {
    const result = parseBulk("evil.com\nEVIL[.]com\nevil.com.");
    expect(result.parsed).toHaveLength(1);
    expect(result.duplicatesInInput).toBe(2);
  });

  it("ignores blank lines and comments", () => {
    const result = parseBulk("# header\n\n8.8.8.8\n\n# trailing");
    expect(result.parsed).toHaveLength(1);
    expect(result.unparsed).toHaveLength(0);
  });

  it("splits comma and tab separated values", () => {
    const result = parseBulk("8.8.8.8, evil.com\t1.1.1.1");
    expect(result.parsed).toHaveLength(3);
  });

  it("does not split a URL containing a comma", () => {
    const result = parseBulk("https://evil.com/a,b");
    expect(result.parsed).toHaveLength(1);
    expect(result.parsed[0].type).toBe("URL");
    expect(result.parsed[0].value).toBe("https://evil.com/a,b");
    expect(result.unparsed).toHaveLength(0);
  });

  it("surfaces unparsable lines instead of dropping them", () => {
    const result = parseBulk("8.8.8.8\nthis is prose\nevil.com");
    expect(result.parsed).toHaveLength(2);
    expect(result.unparsed).toEqual(["this is prose"]);
  });

  it("handles an empty input", () => {
    const result = parseBulk("");
    expect(result.parsed).toHaveLength(0);
    expect(result.unparsed).toHaveLength(0);
  });
});

describe("defang", () => {
  it("makes a URL non-clickable", () => {
    expect(defang("https://evil.com/x")).toBe("hxxps://evil[.]com/x");
  });

  it("round-trips with refang", () => {
    const original = "https://evil.com/x";
    expect(refang(defang(original))).toBe(original);
  });
});
