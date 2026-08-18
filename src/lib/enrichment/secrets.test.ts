import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearCredentialCache,
  decryptSecret,
  encryptSecret,
  getSecret,
  getSecretList,
  loadCredentialCache,
  secretOrigin,
} from "./secrets";

/**
 * Pure crypto + resolution logic, tested without Postgres: `loadCredentialCache`
 * accepts injected rows, so the DB never has to exist here. The full wiring
 * (rows actually stored via the Settings action) is covered by the live
 * verification against the local dev database.
 */

const KEY_B64 = Buffer.alloc(32, 7).toString("base64");

describe("secret encryption", () => {
  beforeEach(() => {
    process.env.CREDENTIAL_ENC_KEY = KEY_B64;
  });

  afterEach(() => {
    clearCredentialCache();
    delete process.env.CREDENTIAL_ENC_KEY;
  });

  it("round-trips a value", () => {
    const encrypted = encryptSecret("super-secret-key");
    expect(encrypted).not.toContain("super-secret-key");
    expect(decryptSecret(encrypted)).toBe("super-secret-key");
  });

  it("is non-deterministic across calls (random IV)", () => {
    expect(encryptSecret("same-key")).not.toBe(encryptSecret("same-key"));
  });

  it("rejects tampering", () => {
    const encrypted = encryptSecret("value");
    const [iv, tag, ct] = encrypted.split(".");
    const flipped = [iv, tag, ct.slice(0, -2) + (ct.endsWith("AA") ? "BB" : "AA")].join(".");
    expect(() => decryptSecret(flipped)).toThrow();
  });

  it("rejects a payload encrypted under a different key", () => {
    const encrypted = encryptSecret("value");
    process.env.CREDENTIAL_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
    expect(() => decryptSecret(encrypted)).toThrow();
  });

  it("accepts a passphrase (non-base64) as the key", () => {
    process.env.CREDENTIAL_ENC_KEY = "a long passphrase that is not base64";
    expect(decryptSecret(encryptSecret("value"))).toBe("value");
  });

  it("throws when CREDENTIAL_ENC_KEY is unset", () => {
    delete process.env.CREDENTIAL_ENC_KEY;
    expect(() => encryptSecret("value")).toThrow(/CREDENTIAL_ENC_KEY/);
  });
});

describe("secret resolution", () => {
  beforeEach(() => {
    process.env.CREDENTIAL_ENC_KEY = KEY_B64;
  });

  afterEach(() => {
    clearCredentialCache();
    delete process.env.CREDENTIAL_ENC_KEY;
    delete process.env.VIRUSTOTAL_API_KEY;
    delete process.env.ABUSEIPDB_API_KEYS;
    delete process.env.ABUSEIPDB_API_KEY;
  });

  it("falls back to env when the cache is empty", () => {
    process.env.VIRUSTOTAL_API_KEY = "env-key";
    expect(getSecret("virustotal")).toBe("env-key");
    expect(secretOrigin("virustotal")).toBe("env");
  });

  it("reports none when nothing is set", () => {
    expect(getSecret("virustotal")).toBeUndefined();
    expect(secretOrigin("virustotal")).toBe("none");
  });

  it("prefers the DB over env once hydrated", async () => {
    process.env.VIRUSTOTAL_API_KEY = "env-key";
    await loadCredentialCache([
      { provider: "virustotal", encValue: encryptSecret("db-key") },
    ]);
    expect(getSecret("virustotal")).toBe("db-key");
    expect(secretOrigin("virustotal")).toBe("db");
  });

  it("keeps env fallback for providers absent from the DB cache", async () => {
    process.env.OTX_API_KEY = "env-key";
    await loadCredentialCache([{ provider: "virustotal", encValue: encryptSecret("db-key") }]);
    expect(getSecret("otx")).toBe("env-key");
    expect(secretOrigin("otx")).toBe("env");
  });

  it("clearing the cache restores env fallback", async () => {
    process.env.VIRUSTOTAL_API_KEY = "env-key";
    await loadCredentialCache([
      { provider: "virustotal", encValue: encryptSecret("db-key") },
    ]);
    clearCredentialCache();
    expect(getSecret("virustotal")).toBe("env-key");
    expect(secretOrigin("virustotal")).toBe("env");
  });

  it("splits a comma list with the multi-key env precedence", () => {
    process.env.ABUSEIPDB_API_KEYS = "k1, k2 ,";
    process.env.ABUSEIPDB_API_KEY = "single";
    expect(getSecretList("abuseipdb")).toEqual(["k1", "k2"]);
  });

  it("falls back to the single abuseipdb env var", () => {
    process.env.ABUSEIPDB_API_KEY = "single";
    expect(getSecretList("abuseipdb")).toEqual(["single"]);
  });

  it("skips undecryptable rows instead of failing the whole cache", async () => {
    await loadCredentialCache([
      { provider: "virustotal", encValue: "not-a-valid-payload" },
      { provider: "otx", encValue: encryptSecret("good-key") },
    ]);
    expect(getSecret("virustotal")).toBeUndefined();
    expect(getSecret("otx")).toBe("good-key");
  });
});
