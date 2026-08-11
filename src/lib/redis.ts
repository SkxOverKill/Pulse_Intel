import Redis from "ioredis";

// Shared by the app and the worker. Not `server-only`: the worker is plain Node.
function createRedis() {
  const url = process.env.REDIS_URL ?? "redis://localhost:6379";
  return new Redis(url, {
    // BullMQ requires this to be null on its own connections; for our direct
    // use, a small retry count fails fast rather than hanging a request.
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
  });
}

const globalForRedis = globalThis as unknown as { redis?: Redis };

export const redis = globalForRedis.redis ?? createRedis();

if (process.env.NODE_ENV !== "production") {
  globalForRedis.redis = redis;
}

/** BullMQ needs its own connection with maxRetriesPerRequest: null. */
export function createQueueConnection() {
  return new Redis(process.env.REDIS_URL ?? "redis://localhost:6379", {
    maxRetriesPerRequest: null,
  });
}
