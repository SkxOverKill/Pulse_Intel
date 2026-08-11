import { describe, expect, it } from "vitest";
import { generateApiKey, hashApiKey, parseBearerToken } from "@/lib/auth/apikey";

describe("generateApiKey", () => {
  it("prefixes the raw key for identifiability", () => {
    const { raw } = generateApiKey();
    expect(raw.startsWith("pulse_")).toBe(true);
  });

  it("derives the prefix from the start of the raw key", () => {
    const { raw, prefix } = generateApiKey();
    expect(raw.startsWith(prefix)).toBe(true);
    expect(prefix.length).toBeLessThan(raw.length);
  });

  it("hash matches hashApiKey(raw), so a stored hash can be looked up later", () => {
    const { raw, hash } = generateApiKey();
    expect(hash).toBe(hashApiKey(raw));
  });

  it("never generates the same key twice", () => {
    const keys = new Set(Array.from({ length: 50 }, () => generateApiKey().raw));
    expect(keys.size).toBe(50);
  });

  it("hash is a sha256 hex digest, not the raw key", () => {
    const { raw, hash } = generateApiKey();
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toBe(raw);
  });
});

describe("hashApiKey", () => {
  it("is deterministic", () => {
    expect(hashApiKey("same-input")).toBe(hashApiKey("same-input"));
  });

  it("differs for different inputs", () => {
    expect(hashApiKey("a")).not.toBe(hashApiKey("b"));
  });
});

describe("parseBearerToken", () => {
  it("extracts the token from a Bearer header", () => {
    expect(parseBearerToken("Bearer pulse_abc123")).toBe("pulse_abc123");
  });

  it("is case-insensitive on the scheme", () => {
    expect(parseBearerToken("bearer pulse_abc123")).toBe("pulse_abc123");
  });

  it("returns null for a missing header", () => {
    expect(parseBearerToken(null)).toBeNull();
  });

  it("returns null for a non-Bearer scheme", () => {
    expect(parseBearerToken("Basic dXNlcjpwYXNz")).toBeNull();
  });

  it("returns null for an empty Bearer value", () => {
    expect(parseBearerToken("Bearer ")).toBeNull();
  });
});
