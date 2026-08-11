import { describe, expect, it } from "vitest";
import { indicatorExpiresAt } from "./decay";

describe("indicator decay", () => {
  const seenAt = new Date("2026-08-11T00:00:00.000Z");

  it("leaves indicators without a half-life active indefinitely", () => {
    expect(indicatorExpiresAt(seenAt, null)).toBeNull();
    expect(indicatorExpiresAt(seenAt, undefined)).toBeNull();
    expect(indicatorExpiresAt(seenAt, 0)).toBeNull();
  });

  it("converts half-life days into an expiry timestamp", () => {
    expect(indicatorExpiresAt(seenAt, 14)?.toISOString()).toBe(
      "2026-08-25T00:00:00.000Z",
    );
  });
});
