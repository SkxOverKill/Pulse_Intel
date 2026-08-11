import "server-only";

import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";
import {
  getPublicApiRateLimitConfig,
  publicApiRateLimitHeaders,
  type PublicApiRateLimitConfig,
  type PublicApiRateLimitDecision,
} from "@/lib/api/rate-limit-config";

export {
  getPublicApiRateLimitConfig,
  publicApiRateLimitHeaders,
  type PublicApiRateLimitConfig,
  type PublicApiRateLimitDecision,
};

function windowKey(identifier: string, now: Date, windowMs: number): string {
  const bucket = Math.floor(now.getTime() / windowMs);
  return `pulse:api-rl:${identifier}:${bucket}`;
}

function resetAt(now: Date, windowMs: number): Date {
  return new Date(Math.ceil((now.getTime() + 1) / windowMs) * windowMs);
}

export async function checkPublicApiRateLimit(
  identifier: string,
  config = getPublicApiRateLimitConfig(),
  now = new Date(),
): Promise<PublicApiRateLimitDecision> {
  const reset = resetAt(now, config.windowMs);
  if (!config.enabled) {
    return { allowed: true, remaining: config.limit, resetAt: reset };
  }

  const key = windowKey(identifier, now, config.windowMs);
  const ttlMs = Math.max(1, reset.getTime() - now.getTime());

  const count = await redis.incr(key);
  if (count === 1) await redis.pexpire(key, ttlMs);

  const remaining = Math.max(0, config.limit - count);
  if (count <= config.limit) {
    return { allowed: true, remaining, resetAt: reset };
  }

  return {
    allowed: false,
    remaining: 0,
    resetAt: reset,
    retryAfterSeconds: Math.max(1, Math.ceil(ttlMs / 1000)),
  };
}

export function publicApiRateLimitResponse(
  config: PublicApiRateLimitConfig,
  decision: Extract<PublicApiRateLimitDecision, { allowed: false }>,
): NextResponse {
  return NextResponse.json(
    {
      error: "Rate limit exceeded.",
      retryAfterSeconds: decision.retryAfterSeconds,
    },
    { status: 429, headers: publicApiRateLimitHeaders(config, decision) },
  );
}
