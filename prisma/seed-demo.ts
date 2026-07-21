/**
 * Demo data — publicly documented threat intelligence.
 *
 * Everything here comes from public MITRE ATT&CK group entries and widely
 * published vendor reporting. The indicators are deliberately RFC 5737 / RFC 2606
 * documentation ranges and example domains, NOT real attacker infrastructure —
 * seeding a database with live IOCs that then get exported to a firewall is a
 * genuinely bad idea.
 *
 * Run with: npm run db:seed:demo
 */
import "dotenv/config";

import { PrismaClient } from "../src/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL is not set.");

const db = new PrismaClient({ adapter: new PrismaPg({ connectionString }) });

const slug = (s: string) =>
  s.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

const ACTORS = [
  {
    name: "APT29",
    attackGroupId: "G0016",
    country: "Russia",
    motivation: "ESPIONAGE",
    sophistication: "STRATEGIC",
    confidence: 90,
    description:
      "Russian state-sponsored group attributed to the SVR. Known for patient, stealthy access to government and diplomatic targets, and for supply-chain compromise.",
    targetSectors: ["Government", "Diplomatic", "Think Tanks", "Technology"],
    targetCountries: ["United States", "United Kingdom", "Germany", "Norway"],
    firstSeen: "2008-01-01",
    aliases: [
      ["Cozy Bear", "CrowdStrike"],
      ["Midnight Blizzard", "Microsoft"],
      ["NOBELIUM", "Microsoft"],
      ["The Dukes", "F-Secure"],
      ["UNC2452", "Mandiant"],
    ],
  },
  {
    name: "APT28",
    attackGroupId: "G0007",
    country: "Russia",
    motivation: "ESPIONAGE",
    sophistication: "EXPERT",
    confidence: 90,
    description:
      "Russian military intelligence (GRU Unit 26165) group active since at least 2004, targeting government, military and security organisations.",
    targetSectors: ["Government", "Defense", "Media", "Energy"],
    targetCountries: ["Ukraine", "United States", "Germany", "France"],
    firstSeen: "2004-01-01",
    aliases: [
      ["Fancy Bear", "CrowdStrike"],
      ["Forest Blizzard", "Microsoft"],
      ["STRONTIUM", "Microsoft"],
      ["Sofacy", "Kaspersky"],
      ["Sednit", "ESET"],
    ],
  },
  {
    name: "Sandworm Team",
    attackGroupId: "G0034",
    country: "Russia",
    motivation: "DESTRUCTION",
    sophistication: "EXPERT",
    confidence: 85,
    description:
      "GRU Unit 74455. Responsible for destructive attacks against Ukrainian critical infrastructure, including the 2015 and 2016 power grid incidents and NotPetya.",
    targetSectors: ["Energy", "Government", "Transportation", "Financial"],
    targetCountries: ["Ukraine", "Poland", "Global"],
    firstSeen: "2009-01-01",
    aliases: [
      ["Voodoo Bear", "CrowdStrike"],
      ["Seashell Blizzard", "Microsoft"],
      ["IRIDIUM", "Microsoft"],
      ["TeleBots", "ESET"],
    ],
  },
  {
    name: "Lazarus Group",
    attackGroupId: "G0032",
    country: "North Korea",
    motivation: "FINANCIAL",
    sophistication: "EXPERT",
    confidence: 88,
    description:
      "North Korean state-sponsored group conducting both espionage and large-scale financially motivated operations, including cryptocurrency theft and bank fraud.",
    targetSectors: ["Financial", "Cryptocurrency", "Defense", "Media"],
    targetCountries: ["South Korea", "United States", "Bangladesh", "Global"],
    firstSeen: "2009-01-01",
    aliases: [
      ["Hidden Cobra", "CISA"],
      ["Diamond Sleet", "Microsoft"],
      ["ZINC", "Microsoft"],
      ["Guardians of Peace", "Self-identified"],
    ],
  },
  {
    name: "APT41",
    attackGroupId: "G0096",
    country: "China",
    motivation: "ESPIONAGE",
    sophistication: "EXPERT",
    confidence: 85,
    description:
      "Chinese group notable for conducting state-sponsored espionage in parallel with financially motivated operations, often using the same infrastructure.",
    targetSectors: ["Healthcare", "Telecommunications", "Technology", "Gaming"],
    targetCountries: ["United States", "United Kingdom", "India", "Japan"],
    firstSeen: "2012-01-01",
    aliases: [
      ["Winnti Group", "Kaspersky"],
      ["Brass Typhoon", "Microsoft"],
      ["BARIUM", "Microsoft"],
      ["Double Dragon", "Mandiant"],
    ],
  },
  {
    name: "Volt Typhoon",
    attackGroupId: "G1017",
    country: "China",
    motivation: "ESPIONAGE",
    sophistication: "ADVANCED",
    confidence: 80,
    description:
      "Chinese state-sponsored group focused on pre-positioning within US critical infrastructure. Relies heavily on living-off-the-land techniques to avoid detection.",
    targetSectors: ["Critical Infrastructure", "Communications", "Utilities", "Transportation"],
    targetCountries: ["United States", "Guam"],
    firstSeen: "2021-01-01",
    aliases: [
      ["VANGUARD PANDA", "CrowdStrike"],
      ["BRONZE SILHOUETTE", "Secureworks"],
    ],
  },
  {
    name: "FIN7",
    attackGroupId: "G0046",
    country: "Unknown",
    motivation: "FINANCIAL",
    sophistication: "ADVANCED",
    confidence: 82,
    description:
      "Financially motivated group targeting retail, restaurant and hospitality sectors, primarily for payment card data. Later shifted toward ransomware operations.",
    targetSectors: ["Retail", "Hospitality", "Restaurant", "Financial"],
    targetCountries: ["United States", "United Kingdom", "Australia"],
    firstSeen: "2013-01-01",
    aliases: [
      ["Carbanak", "Kaspersky"],
      ["Sangria Tempest", "Microsoft"],
      ["ELBRUS", "Microsoft"],
    ],
  },
  {
    name: "Scattered Spider",
    attackGroupId: "G1015",
    country: "Unknown",
    motivation: "FINANCIAL",
    sophistication: "INTERMEDIATE",
    confidence: 75,
    description:
      "Financially motivated group notable for highly effective social engineering, including help-desk impersonation and MFA fatigue, rather than novel malware.",
    targetSectors: ["Telecommunications", "Hospitality", "Retail", "Financial"],
    targetCountries: ["United States", "Canada", "United Kingdom"],
    firstSeen: "2022-01-01",
    aliases: [
      ["Octo Tempest", "Microsoft"],
      ["UNC3944", "Mandiant"],
      ["Muddled Libra", "Palo Alto Unit 42"],
    ],
  },
] as const;

const CAMPAIGNS = [
  {
    name: "SolarWinds Supply Chain Compromise",
    actor: "APT29",
    status: "CONCLUDED",
    confidence: 90,
    startDate: "2020-03-01",
    endDate: "2020-12-01",
    description:
      "Trojanised SolarWinds Orion updates distributed the SUNBURST backdoor to roughly 18,000 organisations, with follow-on exploitation of a much smaller selected subset.",
    targetSectors: ["Government", "Technology", "Consulting"],
    targetCountries: ["United States"],
  },
  {
    name: "NotPetya",
    actor: "Sandworm Team",
    status: "CONCLUDED",
    confidence: 95,
    startDate: "2017-06-27",
    endDate: "2017-07-15",
    description:
      "Destructive wiper disguised as ransomware, initially delivered through compromised M.E.Doc accounting software updates in Ukraine before spreading globally.",
    targetSectors: ["Financial", "Shipping", "Pharmaceutical", "Energy"],
    targetCountries: ["Ukraine", "Global"],
  },
  {
    name: "Critical Infrastructure Pre-positioning",
    actor: "Volt Typhoon",
    status: "ACTIVE",
    confidence: 70,
    startDate: "2021-06-01",
    description:
      "Long-dwell access to US critical infrastructure networks with no observed data theft, assessed as preparation for disruptive action in a future contingency.",
    targetSectors: ["Critical Infrastructure", "Communications", "Utilities"],
    targetCountries: ["United States", "Guam"],
  },
  {
    name: "Unattributed Cloud Credential Harvesting",
    actor: null,
    status: "SUSPECTED",
    confidence: 35,
    startDate: "2026-04-01",
    description:
      "Clustered phishing activity targeting cloud administrator credentials across several sectors. Infrastructure overlaps are suggestive but not sufficient for attribution.",
    targetSectors: ["Technology", "Financial"],
    targetCountries: ["United States", "Germany"],
  },
] as const;

// RFC 5737 / RFC 3849 / RFC 2606 documentation ranges only. Never real IOCs.
const INDICATORS = [
  { type: "IPV4", value: "203.0.113.42", severity: "HIGH", tags: ["c2", "documentation-range"] },
  { type: "IPV4", value: "198.51.100.17", severity: "CRITICAL", tags: ["c2", "documentation-range"] },
  { type: "IPV4", value: "192.0.2.88", severity: "MEDIUM", tags: ["scanner", "documentation-range"] },
  { type: "DOMAIN", value: "malicious.example.com", severity: "HIGH", tags: ["c2", "example-domain"] },
  { type: "DOMAIN", value: "phish.example.org", severity: "HIGH", tags: ["phishing", "example-domain"] },
  { type: "URL", value: "https://payload.example.net/stage2.bin", severity: "CRITICAL", tags: ["payload"] },
  { type: "SHA256", value: "a".repeat(63) + "1", severity: "CRITICAL", tags: ["loader"] },
  { type: "SHA256", value: "b".repeat(63) + "2", severity: "HIGH", tags: ["backdoor"] },
  { type: "MD5", value: "c".repeat(31) + "3", severity: "MEDIUM", tags: ["dropper"] },
  { type: "EMAIL", value: "invoices@phish.example.org", severity: "HIGH", tags: ["phishing"] },
  { type: "CVE", value: "CVE-2024-3400", severity: "CRITICAL", tags: ["exploited", "edge-device"] },
  { type: "CVE", value: "CVE-2021-44228", severity: "CRITICAL", tags: ["log4shell", "exploited"] },
  // Deliberately included: these get auto-whitelisted, demonstrating the filter.
  { type: "IPV4", value: "8.8.8.8", severity: "INFO", tags: ["resolver"] },
  { type: "IPV4", value: "192.168.1.50", severity: "INFO", tags: ["internal"] },
] as const;

const REPORT_BODY = `# Summary

Activity clustered under this report shows credential-harvesting phishing against
cloud administrators, followed by OAuth application consent abuse for persistence.

## Observed infrastructure

Phishing pages were hosted on:

    https://payload.example.net/stage2.bin
    phish.example.org

Command and control beaconing was observed to:

    203.0.113.42
    198.51.100.17

## Samples

    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1
    ccccccccccccccccccccccccccccccc3

## Exploited vulnerabilities

Initial access in two incidents leveraged CVE-2024-3400.

## Assessment

Confidence in a single-actor explanation is low. Infrastructure overlap is
consistent with a shared bulletproof hosting provider rather than a shared
operator, and no distinctive tooling has been recovered.
`;

async function main() {
  const admin = await db.user.findUnique({ where: { email: "admin@pulse.local" } });
  if (!admin) {
    throw new Error("Run `npm run db:seed` first — demo data links to the admin user.");
  }

  console.log("Seeding threat actors…");
  const actorIds = new Map<string, string>();

  for (const a of ACTORS) {
    const actor = await db.threatActor.upsert({
      where: { name: a.name },
      update: {},
      create: {
        name: a.name,
        slug: slug(a.name),
        description: a.description,
        attackGroupId: a.attackGroupId,
        country: a.country,
        motivation: a.motivation,
        sophistication: a.sophistication,
        confidence: a.confidence,
        tlp: "GREEN",
        active: true,
        targetSectors: [...a.targetSectors],
        targetCountries: [...a.targetCountries],
        firstSeen: new Date(a.firstSeen),
        lastSeen: new Date("2026-07-01"),
      },
    });
    actorIds.set(a.name, actor.id);

    for (const [alias, namedBy] of a.aliases) {
      await db.actorAlias.upsert({
        where: { actorId_alias: { actorId: actor.id, alias } },
        update: {},
        create: { actorId: actor.id, alias, namedBy, addedById: admin.id },
      });
    }
    console.log(`  ${a.name.padEnd(20)} ${a.aliases.length} aliases`);
  }

  console.log("\nSeeding campaigns…");
  for (const c of CAMPAIGNS) {
    const campaign = await db.campaign.upsert({
      where: { name: c.name },
      update: {},
      create: {
        name: c.name,
        slug: slug(c.name),
        description: c.description,
        status: c.status,
        confidence: c.confidence,
        tlp: "GREEN",
        startDate: new Date(c.startDate),
        endDate: "endDate" in c && c.endDate ? new Date(c.endDate) : null,
        targetSectors: [...c.targetSectors],
        targetCountries: [...c.targetCountries],
      },
    });

    if (c.actor) {
      const actorId = actorIds.get(c.actor);
      if (actorId) {
        await db.campaignActor.upsert({
          where: { campaignId_actorId: { campaignId: campaign.id, actorId } },
          update: {},
          create: {
            campaignId: campaign.id,
            actorId,
            confidence: c.confidence,
            addedById: admin.id,
          },
        });
      }
    }
    console.log(`  ${c.name.slice(0, 44).padEnd(46)} ${c.actor ?? "unattributed"}`);
  }

  console.log("\nSeeding indicators…");
  const { ingestParsed } = await import("../src/lib/ioc/ingest");
  const { parseIndicator } = await import("../src/lib/ioc/normalize");

  const parsed = INDICATORS.map((i) => parseIndicator(i.value)).filter(
    (p): p is NonNullable<typeof p> => p !== null,
  );
  const report = await ingestParsed(parsed, { confidence: 70, userId: admin.id });
  console.log(
    `  created=${report.created} whitelisted=${report.whitelisted} duplicates=${report.duplicatesInInput}`,
  );

  // Apply the per-indicator severity and tags the ingest defaults don't know about.
  for (const i of INDICATORS) {
    const p = parseIndicator(i.value);
    if (!p) continue;
    await db.indicator.updateMany({
      where: { type: p.type, normalizedValue: p.normalizedValue },
      data: { severity: i.severity, tags: [...i.tags] },
    });
  }

  // Link the highest-severity indicators to APT29 so the pivot UI has content.
  const apt29 = actorIds.get("APT29");
  if (apt29) {
    const linkable = await db.indicator.findMany({
      where: { whitelisted: false, severity: { in: ["HIGH", "CRITICAL"] } },
      take: 6,
      select: { id: true },
    });
    await db.actorIndicator.createMany({
      data: linkable.map((i) => ({
        actorId: apt29,
        indicatorId: i.id,
        confidence: 60,
        addedById: admin.id,
      })),
      skipDuplicates: true,
    });
    console.log(`  linked ${linkable.length} indicators to APT29`);
  }

  console.log("\nSeeding report…");
  await db.report.upsert({
    where: { slug: slug("Cloud Administrator Credential Harvesting") },
    update: {},
    create: {
      title: "Cloud Administrator Credential Harvesting",
      slug: slug("Cloud Administrator Credential Harvesting"),
      summary:
        "Phishing against cloud administrators followed by OAuth consent abuse. Attribution confidence is deliberately low.",
      body: REPORT_BODY,
      published: true,
      publishedAt: new Date("2026-06-15"),
      authorId: admin.id,
      tlp: "GREEN",
      confidence: 40,
      tags: ["phishing", "cloud", "oauth"],
    },
  });

  console.log("\nDone. Sign in and open /actors.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
