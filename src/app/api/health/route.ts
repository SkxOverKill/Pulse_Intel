import { NextResponse } from "next/server";
import packageJson from "../../../../package.json";

export const dynamic = "force-dynamic";

type Check = {
  status: "ok" | "error" | "skipped";
  latencyMs?: number;
  message?: string;
};

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Timed out")), timeoutMs);
    promise
      .then(resolve, reject)
      .finally(() => clearTimeout(timeout));
  });
}

async function timedCheck(fn: () => Promise<void>): Promise<Check> {
  const started = performance.now();
  try {
    await withTimeout(fn(), 1_500);
    return { status: "ok", latencyMs: Math.round(performance.now() - started) };
  } catch (error) {
    return {
      status: "error",
      latencyMs: Math.round(performance.now() - started),
      message: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

async function checkDatabase(): Promise<Check> {
  if (!process.env.DATABASE_URL) {
    return { status: "skipped", message: "DATABASE_URL is not configured" };
  }

  return timedCheck(async () => {
    const { db } = await import("@/lib/db");
    await db.$queryRaw`SELECT 1`;
  });
}

async function checkRedis(): Promise<Check> {
  return timedCheck(async () => {
    const { redis } = await import("@/lib/redis");
    await redis.ping();
  });
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const deep = url.searchParams.get("deep") === "1";

  const checks = deep
    ? {
        database: await checkDatabase(),
        redis: await checkRedis(),
      }
    : undefined;

  const degraded =
    checks && Object.values(checks).some((check) => check.status === "error");

  return NextResponse.json(
    {
      status: degraded ? "degraded" : "ok",
      service: "pulse-intelligence",
      version: packageJson.version,
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
      checks,
    },
    { status: degraded ? 503 : 200 },
  );
}
