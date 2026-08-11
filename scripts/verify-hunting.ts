/**
 * End-to-end verification of the hunt engine against the real database.
 *
 * The unit tests (src/lib/hunting/query.test.ts) prove the AST validates and
 * compiles correctly in isolation. This proves the compiled `where` actually
 * runs against Postgres, that the runner records a run and raises an alert on
 * new matches, and — most importantly — that whitelisted indicators are never
 * matched, which is the one rule a bug here would silently violate.
 *
 * Creates a throwaway hunt, exercises it, and deletes it. Safe to run anytime.
 *
 *   npm run verify:hunting
 */
import "dotenv/config";

import { db } from "../src/lib/db";
import { validateHuntQuery, type HuntQueryAst } from "../src/lib/hunting/schema";
import { compileWhere } from "../src/lib/hunting/compile";
import { previewHunt, runHunt } from "../src/lib/hunting/run";

let failures = 0;
function check(label: string, pass: boolean, detail = "") {
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
  if (!pass) failures++;
}

async function main() {
  console.log("Hunt engine verification\n");

  // A broad query: every non-whitelisted indicator. Exercises the compiler's
  // whitelisted guard against the real table.
  const ast: HuntQueryAst = {
    entity: "indicator",
    match: "all",
    conditions: [{ field: "confidence", op: "gte", value: "0" }],
  };

  const validated = validateHuntQuery(ast);
  check("broad query validates", validated.ok);
  if (!validated.ok) return;

  // Cross-check the compiled count against a direct query that also excludes
  // whitelisted, and against the total including whitelisted.
  const where = compileWhere(validated.ast);
  const [engineCount, nonWhitelisted, whitelisted] = await Promise.all([
    db.indicator.count({ where }),
    db.indicator.count({ where: { whitelisted: false } }),
    db.indicator.count({ where: { whitelisted: true } }),
  ]);

  console.log(
    `\n  table: ${nonWhitelisted} non-whitelisted, ${whitelisted} whitelisted`,
  );
  check(
    "compiled query counts exactly the non-whitelisted indicators",
    engineCount === nonWhitelisted,
    `engine=${engineCount} vs non-whitelisted=${nonWhitelisted}`,
  );
  check(
    "whitelisted indicators are excluded",
    whitelisted === 0 || engineCount < nonWhitelisted + whitelisted,
    whitelisted === 0 ? "none whitelisted to test against" : "confirmed",
  );

  // A narrower query should return a subset, and preview should agree with count.
  const narrow: HuntQueryAst = {
    entity: "indicator",
    match: "all",
    conditions: [{ field: "confidence", op: "gte", value: "70" }],
  };
  const preview = await previewHunt(narrow);
  const narrowCount = await db.indicator.count({ where: compileWhere(narrow) });
  check(
    "preview total matches a direct count",
    preview.total === narrowCount,
    `preview=${preview.total} count=${narrowCount}`,
  );
  check(
    "preview sample is capped and non-empty-safe",
    preview.sample.length <= 50 && preview.sample.length <= preview.total,
    `${preview.sample.length} sampled of ${preview.total}`,
  );

  // Full runner path with alerting. First run has no prior timestamp, so every
  // match is "new" and — because notifyOnHit is on — it must raise one alert.
  console.log("\n  runner + alerting (throwaway hunt)");
  const hunt = await db.huntQuery.create({
    data: {
      name: "__verify_hunting",
      query: narrow as unknown as object,
      notifyOnHit: true,
    },
  });

  try {
    const first = await runHunt(hunt.id);
    check("first run succeeds", first.ok);
    if (first.ok) {
      check(
        "first run matches the same count",
        first.matchCount === narrowCount,
        `${first.matchCount}`,
      );
      check(
        "first run treats matches as new and alerts",
        first.newCount > 0 ? first.alerted : true,
        `new=${first.newCount} alerted=${first.alerted}`,
      );
    }

    const alertsAfterFirst = await db.huntAlert.count({ where: { huntId: hunt.id } });
    check("an alert row was written", alertsAfterFirst === 1, `${alertsAfterFirst}`);

    // Second run immediately after: nothing was created in between, so there
    // should be no *new* matches and no second alert. This is the anti-noise
    // property — a scheduled hunt must not re-alert on the same indicators.
    const second = await runHunt(hunt.id);
    check("second run succeeds", second.ok);
    if (second.ok) {
      check(
        "second run finds no new matches",
        second.newCount === 0,
        `new=${second.newCount}`,
      );
      check("second run raises no alert", !second.alerted);
    }
    const alertsAfterSecond = await db.huntAlert.count({ where: { huntId: hunt.id } });
    check(
      "still exactly one alert after the second run",
      alertsAfterSecond === 1,
      `${alertsAfterSecond}`,
    );

    const reloaded = await db.huntQuery.findUnique({ where: { id: hunt.id } });
    check("run persisted lastRunAt", reloaded?.lastRunAt != null);
    check(
      "run persisted lastHitCount",
      reloaded?.lastHitCount === narrowCount,
      `${reloaded?.lastHitCount}`,
    );
  } finally {
    // Cascade removes the alert rows too.
    await db.huntQuery.delete({ where: { id: hunt.id } });
    console.log("  cleaned up throwaway hunt");
  }

  console.log(
    failures === 0
      ? "\nAll checks passed."
      : `\n${failures} check(s) FAILED.`,
  );
  await db.$disconnect();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
