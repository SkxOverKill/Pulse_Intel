import { redis } from "@/lib/redis";

/**
 * Token-bucket rate limiter, in Redis.
 *
 * This is the piece that makes free-tier enrichment usable at all. VirusTotal
 * allows 4 requests/minute and 500/day; blow through either and the account
 * starts getting 429s. So:
 *
 *   - state lives in Redis, not memory, so it survives worker restarts and is
 *     shared across concurrent workers,
 *   - the check-and-consume is a single Lua script, so two workers cannot both
 *     see "1 token left" and both spend it,
 *   - a refusal reports *when* a token frees up, so callers can schedule rather
 *     than spin.
 */

export type QuotaConfig = {
  perMinute?: number;
  perDay?: number;
};

export type LimiterDecision =
  | { allowed: true }
  | { allowed: false; retryAfterMs: number; reason: "minute" | "day" };

/**
 * Atomically checks both windows and consumes one token from each only if both
 * have room. Returns 0 on success, or the milliseconds to wait.
 *
 * Doing this in Lua matters: a read-then-write in JS lets two workers both pass
 * the check on the last token and produce a 429 that then poisons the whole
 * batch.
 */
const CONSUME = `
local minuteKey = KEYS[1]
local dayKey    = KEYS[2]
local minuteMax = tonumber(ARGV[1])
local dayMax    = tonumber(ARGV[2])
local minuteTtl = tonumber(ARGV[3])
local dayTtl    = tonumber(ARGV[4])

if dayMax > 0 then
  local dayUsed = tonumber(redis.call('GET', dayKey) or '0')
  if dayUsed >= dayMax then
    local ttl = redis.call('PTTL', dayKey)
    if ttl < 0 then ttl = dayTtl end
    return {2, ttl}
  end
end

if minuteMax > 0 then
  local minUsed = tonumber(redis.call('GET', minuteKey) or '0')
  if minUsed >= minuteMax then
    local ttl = redis.call('PTTL', minuteKey)
    if ttl < 0 then ttl = minuteTtl end
    return {1, ttl}
  end
end

-- Both windows have room: consume from each.
if minuteMax > 0 then
  local v = redis.call('INCR', minuteKey)
  if v == 1 then redis.call('PEXPIRE', minuteKey, minuteTtl) end
end
if dayMax > 0 then
  local v = redis.call('INCR', dayKey)
  if v == 1 then redis.call('PEXPIRE', dayKey, dayTtl) end
end

return {0, 0}
`;

function keys(provider: string, now: Date) {
  const minuteBucket = Math.floor(now.getTime() / 60_000);
  const dayBucket = now.toISOString().slice(0, 10);
  return {
    minuteKey: `pulse:rl:${provider}:min:${minuteBucket}`,
    dayKey: `pulse:rl:${provider}:day:${dayBucket}`,
  };
}

/** Milliseconds until the next UTC midnight — when daily quotas reset. */
function msUntilUtcMidnight(now: Date): number {
  const next = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
  );
  return next - now.getTime();
}

export async function consumeToken(
  provider: string,
  quota: QuotaConfig,
  now = new Date(),
): Promise<LimiterDecision> {
  // No configured quota means no limiting (the stub provider, or a paid tier).
  if (!quota.perMinute && !quota.perDay) return { allowed: true };

  const { minuteKey, dayKey } = keys(provider, now);
  const minuteTtl = 60_000 - (now.getTime() % 60_000);
  const dayTtl = msUntilUtcMidnight(now);

  const result = (await redis.eval(
    CONSUME,
    2,
    minuteKey,
    dayKey,
    String(quota.perMinute ?? 0),
    String(quota.perDay ?? 0),
    String(minuteTtl),
    String(dayTtl),
  )) as [number, number];

  const [code, waitMs] = result;
  if (code === 0) return { allowed: true };
  return {
    allowed: false,
    retryAfterMs: Math.max(0, waitMs),
    reason: code === 2 ? "day" : "minute",
  };
}

export type QuotaStatus = {
  provider: string;
  minuteUsed: number;
  minuteMax: number | null;
  dayUsed: number;
  dayMax: number | null;
  dayResetsInMs: number;
};

/** Read-only view for the UI. Never consumes. */
export async function getQuotaStatus(
  provider: string,
  quota: QuotaConfig,
  now = new Date(),
): Promise<QuotaStatus> {
  const { minuteKey, dayKey } = keys(provider, now);
  const [minuteUsed, dayUsed] = await redis.mget(minuteKey, dayKey);

  return {
    provider,
    minuteUsed: Number(minuteUsed ?? 0),
    minuteMax: quota.perMinute ?? null,
    dayUsed: Number(dayUsed ?? 0),
    dayMax: quota.perDay ?? null,
    dayResetsInMs: msUntilUtcMidnight(now),
  };
}

/**
 * How long clearing `count` lookups would take under this quota, in ms.
 * Used to give the UI an honest ETA instead of a spinner that implies "soon".
 */
export function estimateDrainMs(
  count: number,
  quota: QuotaConfig,
  status: { dayUsed: number; dayResetsInMs: number },
): number {
  if (count <= 0) return 0;

  const perMinute = quota.perMinute ?? Infinity;
  const perDay = quota.perDay ?? Infinity;

  const remainingToday = Math.max(0, perDay - status.dayUsed);

  if (count <= remainingToday) {
    return Math.ceil(count / perMinute) * 60_000;
  }

  // Spills past today's quota: today's share, then whole days after that.
  const afterToday = count - remainingToday;
  const fullDays = Math.floor(afterToday / perDay);
  const remainder = afterToday % perDay;

  return (
    status.dayResetsInMs +
    fullDays * 86_400_000 +
    Math.ceil(remainder / perMinute) * 60_000
  );
}
