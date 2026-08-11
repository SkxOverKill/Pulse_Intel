import { describe, expect, it } from "vitest";
import {
  getPublicApiRateLimitConfig,
  publicApiRateLimitHeaders,
} from "./rate-limit-config";

describe("public API rate limit helpers", () => {
  it("uses conservative defaults", () => {
    expect(getPublicApiRateLimitConfig({})).toEqual({
      enabled: true,
      limit: 120,
      windowMs: 60_000,
    });
  });

  it("accepts positive integer environment overrides", () => {
    expect(
      getPublicApiRateLimitConfig({
        PUBLIC_API_RATE_LIMIT_PER_WINDOW: "25",
        PUBLIC_API_RATE_LIMIT_WINDOW_SECONDS: "10",
      }),
    ).toEqual({ enabled: true, limit: 25, windowMs: 10_000 });
  });

  it("falls back on invalid overrides", () => {
    expect(
      getPublicApiRateLimitConfig({
        PUBLIC_API_RATE_LIMIT_PER_WINDOW: "0",
        PUBLIC_API_RATE_LIMIT_WINDOW_SECONDS: "abc",
      }),
    ).toEqual({ enabled: true, limit: 120, windowMs: 60_000 });
  });

  it("emits standard rate limit headers", () => {
    const headers = publicApiRateLimitHeaders(
      { enabled: true, limit: 10, windowMs: 60_000 },
      {
        allowed: false,
        remaining: 0,
        resetAt: new Date("2026-08-11T10:00:00.000Z"),
        retryAfterSeconds: 42,
      },
    );

    expect(headers).toEqual({
      "X-RateLimit-Limit": "10",
      "X-RateLimit-Remaining": "0",
      "X-RateLimit-Reset": "1786442400",
      "Retry-After": "42",
    });
  });
});
