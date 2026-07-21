/**
 * MITRE ATT&CK sync.
 *
 *   npm run attack:sync                          # enterprise, pinned version
 *   npm run attack:sync -- --domain mobile
 *   npm run attack:sync -- --all
 *   npm run attack:sync -- --version 19.0        # explicit upgrade/rollback
 *   npm run attack:sync -- --file ./bundle.json  # offline, from a local bundle
 *   npm run attack:sync -- --no-groups           # skip MITRE's group mappings
 *
 * The version is pinned in src/lib/attack/stix.ts. Upgrading is deliberate:
 * MITRE reshapes fields between releases (v19 moved detection off the technique
 * object entirely), and mappings should never shift because a cron ran.
 *
 * In Phase 5 this becomes a scheduled worker job; the logic already lives in
 * src/lib/attack/sync.ts so nothing needs rewriting.
 */
import "dotenv/config";

import { readFileSync } from "node:fs";
import { ATTACK_VERSION, parseBundle, type AttackDomainKey, type StixBundle } from "../src/lib/attack/stix";
import { ingestParsedBundle, syncAttackDomain, type SyncReport } from "../src/lib/attack/sync";
import { db } from "../src/lib/db";

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const value = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

const DOMAINS: AttackDomainKey[] = ["enterprise", "mobile", "ics"];

function report(r: SyncReport) {
  console.log(`\n  ${r.domain} (ATT&CK v${r.version})`);
  console.log(`    tactics              ${r.tactics}`);
  console.log(`    techniques created   ${r.techniquesCreated}`);
  console.log(`    techniques updated   ${r.techniquesUpdated}`);
  console.log(`    subtechniques linked ${r.subtechniquesLinked}`);
  console.log(
    `    group mappings       ${r.groupMappingsApplied} applied of ${r.groupMappingsAvailable} available`,
  );
}

async function main() {
  const version = value("version") ?? ATTACK_VERSION;
  const applyGroupMappings = !flag("no-groups");
  const localFile = value("file");

  if (localFile) {
    const domain = (value("domain") ?? "enterprise") as AttackDomainKey;
    console.log(`Reading ${localFile} as ${domain}…`);
    const bundle = JSON.parse(readFileSync(localFile, "utf8")) as StixBundle;
    const parsed = parseBundle(bundle);
    report(await ingestParsedBundle(domain, parsed, { applyGroupMappings }));
  } else {
    const domains = flag("all")
      ? DOMAINS
      : [(value("domain") ?? "enterprise") as AttackDomainKey];

    for (const domain of domains) {
      if (!DOMAINS.includes(domain)) {
        throw new Error(`Unknown domain "${domain}". Use: ${DOMAINS.join(", ")}`);
      }
      console.log(`Syncing ${domain} v${version}…`);
      report(await syncAttackDomain(domain, { version, applyGroupMappings }));
    }
  }

  if (!applyGroupMappings) {
    console.log("\n  (group mappings skipped)");
  }
  console.log("\nDone.");
}

main()
  .catch((e) => {
    console.error("\nSync failed:", e instanceof Error ? e.message : e);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
