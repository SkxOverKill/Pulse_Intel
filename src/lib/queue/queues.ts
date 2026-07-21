import { Queue } from "bullmq";
import { createQueueConnection } from "@/lib/redis";

/**
 * Queue definitions, shared by the app (which enqueues) and the worker (which
 * consumes).
 *
 * Priority is the important detail. BullMQ treats *lower* numbers as higher
 * priority, so an analyst clicking "enrich this now" jumps ahead of a 10,000-row
 * bulk import that may be days from finishing. A human waiting beats a
 * background job, always.
 */

export const PRIORITY = {
  INTERACTIVE: 1,
  BULK: 10,
  BACKGROUND: 20,
} as const;

// No colons: BullMQ reserves ':' for its own Redis key namespacing and rejects
// queue names containing it.
export const QUEUE_NAMES = {
  enrichment: "pulse-enrichment",
  feeds: "pulse-feeds",
} as const;

export type EnrichmentJob = {
  indicatorId: string;
  /** Omit to run every provider that supports the indicator's type. */
  provider?: string;
  force?: boolean;
  /** Groups jobs from one bulk import so the UI can report on them together. */
  batchId?: string;
};

export type FeedJob = {
  sourceId: string;
  /** Set for scheduled runs, so manual runs can be told apart in the log. */
  scheduled?: boolean;
};

const globalForQueues = globalThis as unknown as {
  enrichmentQueue?: Queue<EnrichmentJob>;
  feedQueue?: Queue<FeedJob>;
};

function makeQueue<T>(name: string): Queue<T> {
  return new Queue<T>(name, {
    connection: createQueueConnection(),
    defaultJobOptions: {
      // A rate-limited provider is a normal condition, not a failure, so
      // backoff is generous rather than aggressive.
      attempts: 3,
      backoff: { type: "exponential", delay: 30_000 },
      removeOnComplete: { count: 1000, age: 24 * 3600 },
      removeOnFail: { count: 5000, age: 7 * 24 * 3600 },
    },
  });
}

export const enrichmentQueue: Queue<EnrichmentJob> =
  globalForQueues.enrichmentQueue ?? makeQueue<EnrichmentJob>(QUEUE_NAMES.enrichment);

export const feedQueue: Queue<FeedJob> =
  globalForQueues.feedQueue ?? makeQueue<FeedJob>(QUEUE_NAMES.feeds);

if (process.env.NODE_ENV !== "production") {
  globalForQueues.enrichmentQueue = enrichmentQueue;
  globalForQueues.feedQueue = feedQueue;
}

export async function enqueueEnrichment(
  jobs: EnrichmentJob[],
  priority: number = PRIORITY.BULK,
) {
  if (jobs.length === 0) return 0;
  await enrichmentQueue.addBulk(
    jobs.map((data) => ({
      name: "enrich",
      data,
      opts: {
        priority,
        // Deduplicate: re-queuing the same indicator+provider while one is
        // already pending would waste quota on identical work.
        // Separator is '__' not ':' — BullMQ rejects colons in custom job ids,
        // the same restriction it applies to queue names.
        jobId: `${data.indicatorId}__${data.provider ?? "all"}${data.force ? "__force" : ""}`,
      },
    })),
  );
  return jobs.length;
}

export async function enqueueFeed(sourceId: string, scheduled = false) {
  return feedQueue.add(
    "run-feed",
    { sourceId, scheduled },
    {
      priority: scheduled ? PRIORITY.BACKGROUND : PRIORITY.INTERACTIVE,
      // Minute-bucketed so double-clicking "run now" collapses to one run.
      jobId: `feed__${sourceId}__${Math.floor(Date.now() / 60_000)}`,
    },
  );
}

export async function getQueueStats() {
  const [enrichCounts, feedCounts] = await Promise.all([
    enrichmentQueue.getJobCounts("waiting", "active", "delayed", "failed", "completed"),
    feedQueue.getJobCounts("waiting", "active", "delayed", "failed", "completed"),
  ]);
  return { enrichment: enrichCounts, feeds: feedCounts };
}
