export type PublicApiRateLimitConfig = {
  enabled: boolean;
  limit: number;
  windowMs: number;
};

export type PublicApiRateLimitDecision =
  | { allowed: true; remaining: number; resetAt: Date }
  | { allowed: false; remaining: 0; resetAt: Date; retryAfterSeconds: number };

const DEFAULT_LIMIT = 120;
const DEFAULT_WINDOW_SECONDS = 60;

function positiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function getPublicApiRateLimitConfig(
  env: Record<string, string | undefined> = process.env,
): PublicApiRateLimitConfig {
  return {
    enabled: env.PUBLIC_API_RATE_LIMIT_DISABLED !== "1",
    limit: positiveInt(env.PUBLIC_API_RATE_LIMIT_PER_WINDOW, DEFAULT_LIMIT),
    windowMs:
      positiveInt(env.PUBLIC_API_RATE_LIMIT_WINDOW_SECONDS, DEFAULT_WINDOW_SECONDS) *
      1000,
  };
}

export function publicApiRateLimitHeaders(
  config: PublicApiRateLimitConfig,
  decision: PublicApiRateLimitDecision,
): Record<string, string> {
  const headers: Record<string, string> = {
    "X-RateLimit-Limit": String(config.limit),
    "X-RateLimit-Remaining": String(decision.remaining),
    "X-RateLimit-Reset": String(Math.ceil(decision.resetAt.getTime() / 1000)),
  };

  if (!decision.allowed) {
    headers["Retry-After"] = String(decision.retryAfterSeconds);
  }

  return headers;
}
