import { describe, expect, it } from "vitest";
import { estimateDrainMs } from "./limiter";

/**
 * estimateDrainMs is pure, so it is tested directly. The Redis consume path is
 * covered by scripts/verify-enrichment.ts against a live server, since its whole
 * point is atomicity under concurrency — which a mock cannot demonstrate.
 */

const VT = { perMinute: 4, perDay: 500 };
const HOUR = 3_600_000;
const DAY = 86_400_000;

describe("estimateDrainMs", () => {
  const fresh = { dayUsed: 0, dayResetsInMs: 12 * HOUR };

  it("is zero for no work", () => {
    expect(estimateDrainMs(0, VT, fresh)).toBe(0);
  });

  it("rounds up to whole minutes within the per-minute rate", () => {
    // 4/min: 4 items still occupies a minute.
    expect(estimateDrainMs(4, VT, fresh)).toBe(60_000);
    expect(estimateDrainMs(5, VT, fresh)).toBe(120_000);
  });

  it("handles a batch that fits inside today's remaining quota", () => {
    // 100 items at 4/min = 25 minutes.
    expect(estimateDrainMs(100, VT, fresh)).toBe(25 * 60_000);
  });

  it("accounts for quota already spent today", () => {
    const used = { dayUsed: 490, dayResetsInMs: 6 * HOUR };
    // Only 10 left today; the other 40 wait for tomorrow's reset.
    const ms = estimateDrainMs(50, VT, used);
    expect(ms).toBeGreaterThan(6 * HOUR);
  });

  it("spans multiple days for a batch larger than the daily quota", () => {
    // The headline case: 10,000 IOCs against VirusTotal's 500/day.
    const ms = estimateDrainMs(10_000, VT, fresh);
    const days = ms / DAY;
    expect(days).toBeGreaterThan(18);
    expect(days).toBeLessThan(21);
  });

  it("is unbounded-fast when no quota is configured", () => {
    expect(estimateDrainMs(1_000_000, {}, fresh)).toBe(0);
  });

  it("treats a daily-only quota sensibly", () => {
    // AbuseIPDB: 1,000/day, no per-minute limit.
    const abuse = { perDay: 1000 };
    expect(estimateDrainMs(500, abuse, fresh)).toBe(0);
    expect(estimateDrainMs(1500, abuse, fresh)).toBeGreaterThanOrEqual(
      fresh.dayResetsInMs,
    );
  });

  it("never returns a negative estimate", () => {
    const overspent = { dayUsed: 999_999, dayResetsInMs: 1000 };
    expect(estimateDrainMs(10, VT, overspent)).toBeGreaterThanOrEqual(0);
  });
});
