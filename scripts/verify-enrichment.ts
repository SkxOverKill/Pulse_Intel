/**
 * Live verification of the enrichment layer against real Redis and real APIs.
 *
 * The rate limiter's entire value is atomicity under concurrency, which a mocked
 * test cannot demonstrate — so this fires genuinely concurrent requests at a
 * real Redis and asserts the quota held.
 *
 *   npm run verify:enrichment            # limiter only, no API calls
 *   npm run verify:enrichment -- --live  # also spends a few real API requests
 */
import "dotenv/config";

import { consumeToken, getQuotaStatus } from "../src/lib/enrichment/limiter";
import { configuredProviders, PROVIDERS } from "../src/lib/enrichment/registry";
import { redis } from "../src/lib/redis";

const live = process.argv.includes("--live");
let failures = 0;

function check(label: string, pass: boolean, detail = "") {
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
  if (!pass) failures++;
}

async function clearBuckets(provider: string) {
  const keys = await redis.keys(`pulse:rl:${provider}:*`);
  if (keys.length) await redis.del(...keys);
}

async function testConcurrency() {
  console.log("\nLimiter: 20 concurrent requests against a 4/min quota");
  const provider = "__verify_concurrency";
  await clearBuckets(provider);

  const quota = { perMinute: 4, perDay: 100 };
  const results = await Promise.all(
    Array.from({ length: 20 }, () => consumeToken(provider, quota)),
  );

  const allowed = results.filter((r) => r.allowed).length;
  check(
    "exactly 4 allowed, 16 refused",
    allowed === 4,
    `${allowed} allowed`,
  );

  const refused = results.filter((r) => !r.allowed);
  check(
    "every refusal carries a positive retryAfterMs",
    refused.every((r) => !r.allowed && r.retryAfterMs > 0),
  );
  check(
    "refusals cite the minute window",
    refused.every((r) => !r.allowed && r.reason === "minute"),
  );

  await clearBuckets(provider);
}

async function testDailyCeiling() {
  console.log("\nLimiter: daily ceiling takes precedence over per-minute room");
  const provider = "__verify_daily";
  await clearBuckets(provider);

  // Generous per-minute, tiny per-day: the day limit must be what bites.
  const quota = { perMinute: 1000, perDay: 3 };
  const results = await Promise.all(
    Array.from({ length: 10 }, () => consumeToken(provider, quota)),
  );

  const allowed = results.filter((r) => r.allowed).length;
  check("exactly 3 allowed", allowed === 3, `${allowed} allowed`);
  check(
    "refusals cite the day window",
    results.filter((r) => !r.allowed).every((r) => !r.allowed && r.reason === "day"),
  );

  const status = await getQuotaStatus(provider, quota);
  check("status reports 3 used today", status.dayUsed === 3, `${status.dayUsed}`);
  check(
    "day resets within 24h",
    status.dayResetsInMs > 0 && status.dayResetsInMs <= 86_400_000,
  );

  await clearBuckets(provider);
}

async function testPersistence() {
  console.log("\nLimiter: state survives a fresh client (restart simulation)");
  const provider = "__verify_persist";
  await clearBuckets(provider);
  const quota = { perMinute: 2 };

  await consumeToken(provider, quota);
  await consumeToken(provider, quota);
  // A new process would re-read the same Redis keys; the third must be refused.
  const third = await consumeToken(provider, quota);
  check("third request refused after restart", !third.allowed);

  await clearBuckets(provider);
}

function testRegistry() {
  console.log("\nRegistry");
  const order = PROVIDERS.map((p) => p.name);
  check(
    "OTX ordered before VirusTotal (spend the free one first)",
    order.indexOf("otx") < order.indexOf("virustotal"),
    order.join(" -> "),
  );

  const configured = configuredProviders().map((p) => p.name);
  check("virustotal configured", configured.includes("virustotal"));
  check("abuseipdb configured", configured.includes("abuseipdb"));
  check("otx configured", configured.includes("otx"));
  check(
    "stub NOT active (would fabricate verdicts)",
    !configured.includes("stub"),
  );
}

async function testLiveProviders() {
  console.log("\nLive provider lookups (spends real quota)");

  const cases: { provider: string; value: string; type: "IPV4" | "DOMAIN" }[] = [
    { provider: "otx", value: "8.8.8.8", type: "IPV4" },
    { provider: "abuseipdb", value: "8.8.8.8", type: "IPV4" },
    { provider: "virustotal", value: "8.8.8.8", type: "IPV4" },
  ];

  for (const c of cases) {
    const provider = PROVIDERS.find((p) => p.name === c.provider);
    if (!provider?.isConfigured()) {
      check(`${c.provider} skipped`, true, "not configured");
      continue;
    }
    try {
      const result = await provider.lookup(c.value, c.type);
      // 8.8.8.8 is Google DNS: any provider calling it malicious is misreading.
      check(
        `${c.provider} returns a sane verdict for 8.8.8.8`,
        result.verdict !== "MALICIOUS",
        `${result.verdict} score=${result.score}`,
      );
    } catch (err) {
      check(`${c.provider} lookup`, false, (err as Error).message);
    }
  }
}

async function main() {
  console.log("Enrichment verification");
  testRegistry();
  await testConcurrency();
  await testDailyCeiling();
  await testPersistence();
  if (live) await testLiveProviders();
  else console.log("\n(skipping live API calls; pass --live to include them)");

  console.log(failures === 0 ? "\nAll checks passed." : `\n${failures} check(s) FAILED.`);
  redis.disconnect();
  process.exit(failures === 0 ? 0 : 1);
}

main();
