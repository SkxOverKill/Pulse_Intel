import { describe, expect, it } from "vitest";
import { isWhitelisted, whitelistReason } from "./whitelist";

describe("whitelistReason", () => {
  it("catches RFC1918 and loopback addresses", () => {
    for (const ip of ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"]) {
      expect(whitelistReason("IPV4", ip)).toBeTruthy();
    }
  });

  it("does not whitelist a public address just outside RFC1918", () => {
    // 172.32.x is public — the /12 boundary is a classic off-by-one.
    expect(whitelistReason("IPV4", "172.32.0.1")).toBeNull();
    expect(whitelistReason("IPV4", "11.0.0.1")).toBeNull();
    expect(whitelistReason("IPV4", "192.169.1.1")).toBeNull();
  });

  it("catches well-known public resolvers", () => {
    expect(whitelistReason("IPV4", "8.8.8.8")).toBeTruthy();
    expect(whitelistReason("IPV4", "1.1.1.1")).toBeTruthy();
  });

  it("catches infrastructure domains and their subdomains", () => {
    expect(whitelistReason("DOMAIN", "google.com")).toBeTruthy();
    expect(whitelistReason("DOMAIN", "www.google.com")).toBeTruthy();
    expect(whitelistReason("DOMAIN", "update.windowsupdate.com")).toBeTruthy();
  });

  it("does not whitelist a lookalike domain", () => {
    // The whole point: notgoogle.com must not inherit google.com's exemption.
    expect(whitelistReason("DOMAIN", "notgoogle.com")).toBeNull();
    expect(whitelistReason("DOMAIN", "google.com.evil.ru")).toBeNull();
    expect(whitelistReason("DOMAIN", "evil-github.com")).toBeNull();
  });

  it("catches URLs pointing at infrastructure domains", () => {
    expect(whitelistReason("URL", "https://www.google.com/a")).toBeTruthy();
    expect(whitelistReason("URL", "https://evil.com/a")).toBeNull();
  });

  it("catches empty-file hashes", () => {
    expect(
      whitelistReason("MD5", "d41d8cd98f00b204e9800998ecf8427e"),
    ).toBeTruthy();
    expect(
      whitelistReason("SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ).toBeTruthy();
  });

  it("leaves ordinary indicators alone", () => {
    expect(whitelistReason("IPV4", "45.33.32.156")).toBeNull();
    expect(whitelistReason("DOMAIN", "evil.com")).toBeNull();
    expect(whitelistReason("SHA256", "a".repeat(64))).toBeNull();
    expect(whitelistReason("CVE", "CVE-2024-3400")).toBeNull();
  });

  it("isWhitelisted mirrors whitelistReason", () => {
    expect(isWhitelisted("IPV4", "10.0.0.1")).toBe(true);
    expect(isWhitelisted("IPV4", "45.33.32.156")).toBe(false);
  });
});
