/**
 * End-to-end verification of the public REST API against the real running
 * server (npm run dev must be up on PULSE_BASE_URL, default localhost:3000).
 *
 * Creates a throwaway API key directly via the db (bypassing the UI, same
 * hashing path as createApiKey), exercises auth failure modes and both
 * resource families, and confirms the one rule a bug here would silently
 * violate: whitelisted indicators must never be reachable through the public
 * API, in list or detail form. Cleans up after itself.
 *
 *   npm run verify:api
 */
import "dotenv/config";

import { db } from "../src/lib/db";
import { generateApiKey } from "../src/lib/auth/apikey";

const BASE = process.env.PULSE_BASE_URL ?? "http://localhost:3000";

let failures = 0;
function check(label: string, pass: boolean, detail = "") {
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
  if (!pass) failures++;
}

async function main() {
  console.log("Public API verification\n");

  const user = await db.user.findFirst({ where: { email: "admin@pulse.local" } });
  if (!user) throw new Error("Seed the database first (npm run db:seed).");

  const full = generateApiKey();
  const fullKey = await db.apiKey.create({
    data: { name: "__verify_api_full", keyHash: full.hash, prefix: full.prefix, userId: user.id },
  });

  const scoped = generateApiKey();
  const scopedKey = await db.apiKey.create({
    data: {
      name: "__verify_api_scoped",
      keyHash: scoped.hash,
      prefix: scoped.prefix,
      userId: user.id,
      scopes: ["actors:read"],
    },
  });

  const revoked = generateApiKey();
  const revokedKey = await db.apiKey.create({
    data: {
      name: "__verify_api_revoked",
      keyHash: revoked.hash,
      prefix: revoked.prefix,
      userId: user.id,
      revoked: true,
    },
  });

  try {
    console.log("auth");
    const noAuth = await fetch(`${BASE}/api/v1/indicators`);
    check("missing bearer token is rejected", noAuth.status === 401);

    const badAuth = await fetch(`${BASE}/api/v1/indicators`, {
      headers: { Authorization: "Bearer not-a-real-key" },
    });
    check("unknown key is rejected", badAuth.status === 401);

    const revokedAuth = await fetch(`${BASE}/api/v1/indicators`, {
      headers: { Authorization: `Bearer ${revoked.raw}` },
    });
    check("revoked key is rejected", revokedAuth.status === 401);

    const scopeDenied = await fetch(`${BASE}/api/v1/indicators`, {
      headers: { Authorization: `Bearer ${scoped.raw}` },
    });
    check(
      "a key scoped to actors:read cannot read indicators",
      scopeDenied.status === 403,
      `got ${scopeDenied.status}`,
    );

    const scopeGranted = await fetch(`${BASE}/api/v1/actors`, {
      headers: { Authorization: `Bearer ${scoped.raw}` },
    });
    check(
      "the same key can read actors",
      scopeGranted.status === 200,
      `got ${scopeGranted.status}`,
    );

    console.log("\nindicators");
    const [dbNonWhitelisted, dbWhitelisted] = await Promise.all([
      db.indicator.count({ where: { whitelisted: false } }),
      db.indicator.findFirst({ where: { whitelisted: true } }),
    ]);

    const list = await fetch(`${BASE}/api/v1/indicators?pageSize=500`, {
      headers: { Authorization: `Bearer ${full.raw}` },
    });
    const listBody = await list.json();
    check("list returns 200", list.status === 200);
    check(
      "list total matches non-whitelisted count",
      listBody.total === dbNonWhitelisted,
      `api=${listBody.total} db=${dbNonWhitelisted}`,
    );

    if (dbWhitelisted) {
      const detail = await fetch(`${BASE}/api/v1/indicators/${dbWhitelisted.id}`, {
        headers: { Authorization: `Bearer ${full.raw}` },
      });
      check(
        "a whitelisted indicator 404s on the detail route",
        detail.status === 404,
        `got ${detail.status}`,
      );
    } else {
      console.log("  SKIP  no whitelisted indicator in this DB to test against");
    }

    const notFound = await fetch(`${BASE}/api/v1/indicators/does-not-exist`, {
      headers: { Authorization: `Bearer ${full.raw}` },
    });
    check("a nonexistent id 404s the same way", notFound.status === 404);

    const csv = await fetch(`${BASE}/api/v1/indicators?format=csv&pageSize=5`, {
      headers: { Authorization: `Bearer ${full.raw}` },
    });
    const csvBody = await csv.text();
    check(
      "format=csv returns a CSV body via the shared formatter",
      csv.status === 200 && csvBody.startsWith("type,value,confidence"),
    );

    console.log("\nactors");
    const actors = await fetch(`${BASE}/api/v1/actors`, {
      headers: { Authorization: `Bearer ${full.raw}` },
    });
    const actorsBody = await actors.json();
    check("actors list returns 200 with data", actors.status === 200 && Array.isArray(actorsBody.data));

    if (actorsBody.data.length > 0) {
      const firstId = actorsBody.data[0].id;
      const detail = await fetch(`${BASE}/api/v1/actors/${firstId}`, {
        headers: { Authorization: `Bearer ${full.raw}` },
      });
      const detailBody = await detail.json();
      check("actor detail returns 200", detail.status === 200);
      check(
        "actor detail's techniques carry their own confidence (attribution is opinion, not fact)",
        detail.status !== 200 ||
          detailBody.data.techniques.every((t: { confidence: unknown }) => typeof t.confidence === "number"),
      );
    } else {
      console.log("  SKIP  no actors in this DB to test detail against");
    }

    console.log("\nusage tracking");
    // `full.raw` was already used above (list, csv), so lastUsedAt is non-null
    // by now — the real assertion is that a *fresh* call moves it forward, not
    // that it starts empty.
    const before = await db.apiKey.findUnique({ where: { id: fullKey.id } });
    check("lastUsedAt was set by the earlier calls", before?.lastUsedAt != null);
    await new Promise((r) => setTimeout(r, 20));
    await fetch(`${BASE}/api/v1/actors`, { headers: { Authorization: `Bearer ${full.raw}` } });
    await new Promise((r) => setTimeout(r, 300)); // lastUsedAt write is fire-and-forget
    const after = await db.apiKey.findUnique({ where: { id: fullKey.id } });
    check(
      "a subsequent call advances lastUsedAt",
      !!after?.lastUsedAt && !!before?.lastUsedAt && after.lastUsedAt > before.lastUsedAt,
    );
  } finally {
    await db.apiKey.deleteMany({
      where: { id: { in: [fullKey.id, scopedKey.id, revokedKey.id] } },
    });
    console.log("\ncleaned up throwaway API keys");
  }

  console.log(failures === 0 ? "\nAll checks passed." : `\n${failures} check(s) FAILED.`);
  await db.$disconnect();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
