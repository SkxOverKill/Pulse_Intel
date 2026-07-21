/**
 * Background worker.
 *
 * Runs enrichment and feed ingestion, and owns the recurring schedule. Shares
 * src/lib with the Next app, so domain logic exists once — which is exactly why
 * nothing in src/lib/ioc, src/lib/feeds or src/lib/enrichment may be marked
 * `server-only` (it throws on import outside a bundler).
 *
 *   npm run worker
 */
import "dotenv/config";

import { Worker, type Job } from "bullmq";
import { db } from "@/lib/db";
import { createQueueConnection } from "@/lib/redis";
import {
  QUEUE_NAMES,
  enqueueFeed,
  feedQueue,
  type EnrichmentJob,
  type FeedJob,
} from "@/lib/queue/queues";
import { enrichAll, enrichOne, recomputeIndicatorConfidence } from "@/lib/enrichment/enrich";
import { runFeed } from "@/lib/feeds/run";

const log = (...args: unknown[]) =>
  console.log(new Date().toISOString(), ...args);

// --- Enrichment worker ----------------------------------------------------

const enrichmentWorker = new Worker<EnrichmentJob>(
  QUEUE_NAMES.enrichment,
  async (job: Job<EnrichmentJob>) => {
    const { indicatorId, provider, force } = job.data;

    const outcomes = provider
      ? [await enrichOne(indicatorId, provider, { force })]
      : await enrichAll(indicatorId, { force });

    // A rate-limited job is not a failure — it is the system working as
    // designed. Reschedule it past the reset instead of burning an attempt.
    const limited = outcomes.find((o) => o.status === "rate_limited");
    if (limited && limited.status === "rate_limited") {
      await job.moveToDelayed(Date.now() + Math.max(1000, limited.retryAfterMs));
      return { deferred: true, retryAfterMs: limited.retryAfterMs };
    }

    if (outcomes.some((o) => o.status === "fetched")) {
      await recomputeIndicatorConfidence(indicatorId);
    }

    return { outcomes };
  },
  {
    connection: createQueueConnection(),
    // Deliberately low. The providers' own quotas are the real constraint, and
    // high concurrency would just pile up rate-limit deferrals.
    concurrency: 4,
  },
);

// --- Feed worker ----------------------------------------------------------

const feedWorker = new Worker<FeedJob>(
  QUEUE_NAMES.feeds,
  async (job: Job<FeedJob>) => {
    const result = await runFeed(job.data.sourceId);
    log(
      `feed  ${result.ok ? "ok  " : "FAIL"} ${result.sourceName} — ${result.message}`,
    );
    if (!result.ok) throw new Error(result.message);
    return result;
  },
  {
    connection: createQueueConnection(),
    // Feeds are network-bound and hit distinct hosts, so a little parallelism
    // is safe; too much and we look like a scraper.
    concurrency: 3,
  },
);

// --- Scheduling -----------------------------------------------------------

/**
 * Installs a repeatable job per enabled source, using each source's own cron.
 *
 * Re-syncs on every boot so schedule edits in the UI take effect, and removes
 * schedulers for sources that were disabled or deleted — otherwise a disabled
 * feed keeps firing forever.
 */
async function syncSchedules() {
  const sources = await db.source.findMany({
    where: { enabled: true, schedule: { not: null } },
    select: { id: true, name: true, schedule: true },
  });

  const wanted = new Set(sources.map((s) => `src:${s.id}`));

  const existing = await feedQueue.getJobSchedulers();
  for (const sched of existing) {
    if (sched.key && !wanted.has(sched.key)) {
      await feedQueue.removeJobScheduler(sched.key);
      log(`schedule removed ${sched.key}`);
    }
  }

  for (const s of sources) {
    await feedQueue.upsertJobScheduler(
      `src:${s.id}`,
      { pattern: s.schedule! },
      { name: "run-feed", data: { sourceId: s.id, scheduled: true } },
    );
  }

  log(`scheduled ${sources.length} feed(s)`);
  return sources.length;
}

/** Runs every enabled feed immediately — used on boot and by `--run-now`. */
async function runAllFeedsNow() {
  const sources = await db.source.findMany({
    where: { enabled: true },
    select: { id: true, name: true },
  });
  for (const s of sources) await enqueueFeed(s.id, false);
  log(`queued ${sources.length} feed(s) for immediate run`);
  return sources.length;
}

// --- Lifecycle ------------------------------------------------------------

enrichmentWorker.on("failed", (job, err) =>
  log(`enrich FAIL ${job?.data.indicatorId ?? "?"} — ${err.message}`),
);
feedWorker.on("failed", (job, err) =>
  log(`feed   FAIL ${job?.data.sourceId ?? "?"} — ${err.message}`),
);

async function shutdown(signal: string) {
  log(`${signal} received, draining…`);
  await Promise.allSettled([enrichmentWorker.close(), feedWorker.close()]);
  await db.$disconnect();
  process.exit(0);
}
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

async function main() {
  log("Pulse worker starting");
  await syncSchedules();

  if (process.argv.includes("--run-now")) {
    await runAllFeedsNow();
  }

  // Re-read schedules periodically so changes made in the UI are picked up
  // without a restart.
  setInterval(() => void syncSchedules().catch((e) => log("schedule sync failed", e)), 5 * 60_000);

  log("worker ready — enrichment + feeds");
}

main().catch((err) => {
  console.error("worker failed to start:", err);
  process.exit(1);
});
