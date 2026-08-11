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
  {
    name: "Microsoft Teams Device-Code Phishing",
    actor: "APT29",
    status: "ACTIVE",
    confidence: 85,
    startDate: "2023-08-01",
    description:
      "Highly targeted social engineering via Microsoft Teams messages impersonating technical support or security personnel, abusing OAuth device-code authentication flows to hijack sessions without needing the victim's password.",
    targetSectors: ["Government", "Technology", "Defense", "NGO"],
    targetCountries: ["United States", "United Kingdom", "European Union"],
  },
  {
    name: "WinRAR Zero-Day Exploitation (CVE-2023-38831)",
    actor: "APT28",
    status: "CONCLUDED",
    confidence: 80,
    startDate: "2023-04-01",
    endDate: "2023-10-01",
    description:
      "Phishing campaign exploiting a WinRAR path-traversal flaw that let a decoy document silently execute an attacker script when opened, primarily against Ukrainian government and energy-sector targets.",
    targetSectors: ["Government", "Energy"],
    targetCountries: ["Ukraine"],
  },
  {
    name: "Industroyer2 Ukraine Power Grid Attack",
    actor: "Sandworm Team",
    status: "CONCLUDED",
    confidence: 95,
    startDate: "2022-04-01",
    endDate: "2022-04-08",
    description:
      "Deployment of an updated Industroyer variant against a Ukrainian energy provider's high-voltage substations, intended to cause an outage. Detected and contained before the disruptive payload executed.",
    targetSectors: ["Energy", "Critical Infrastructure"],
    targetCountries: ["Ukraine"],
  },
  {
    name: "3CX Supply Chain Compromise",
    actor: "Lazarus Group",
    status: "CONCLUDED",
    confidence: 90,
    startDate: "2023-02-01",
    endDate: "2023-04-01",
    description:
      "Trojanised 3CX desktop softphone installers distributed a multi-stage backdoor to the software's customers — itself the result of an earlier compromise of a financial trading application whose installer an employee had downloaded, making this a rare double supply-chain attack.",
    targetSectors: ["Technology", "Telecommunications"],
    targetCountries: ["Global"],
  },
  {
    name: "JumpCloud Directory Platform Intrusion",
    actor: "Lazarus Group",
    status: "CONCLUDED",
    confidence: 75,
    startDate: "2023-06-01",
    endDate: "2023-07-01",
    description:
      "Spear-phishing intrusion into JumpCloud's identity/directory platform, followed by targeted abuse of its command-execution framework against a small number of downstream cryptocurrency-sector customers.",
    targetSectors: ["Technology", "Cryptocurrency"],
    targetCountries: ["United States"],
  },
  {
    name: "US State Government Zero-Day Intrusions",
    actor: "APT41",
    status: "CONCLUDED",
    confidence: 85,
    startDate: "2021-05-01",
    endDate: "2022-02-01",
    description:
      "Exploitation of a zero-day in a livestock-management web application to compromise at least six US state government networks, alongside parallel exploitation of USAHerds and Log4Shell against other victims in the same operation.",
    targetSectors: ["Government"],
    targetCountries: ["United States"],
  },
  {
    name: "KV Botnet Living-off-the-Land Access",
    actor: "Volt Typhoon",
    status: "ACTIVE",
    confidence: 80,
    startDate: "2023-01-01",
    description:
      "Compromise of end-of-life SOHO routers and firewalls to build a covert proxy network, used to route living-off-the-land access into US critical infrastructure so it blends into ordinary residential traffic. FBI court-authorised operation disrupted the botnet's infrastructure in January 2024, but the underlying access model is assessed to be still in use.",
    targetSectors: ["Critical Infrastructure", "Communications"],
    targetCountries: ["United States"],
  },
  {
    name: "Black Basta Ransomware Affiliate Operations",
    actor: "FIN7",
    status: "ACTIVE",
    confidence: 70,
    startDate: "2022-04-01",
    description:
      "Financially motivated intrusions using FIN7's established loader and backdoor tooling to hand off access to the Black Basta ransomware-as-a-service operation for encryption and extortion.",
    targetSectors: ["Manufacturing", "Healthcare", "Professional Services"],
    targetCountries: ["United States", "European Union"],
  },
  {
    name: "MGM Resorts & Caesars Entertainment Ransomware Attacks",
    actor: "Scattered Spider",
    status: "CONCLUDED",
    confidence: 90,
    startDate: "2023-09-01",
    endDate: "2023-09-15",
    description:
      "Voice-phishing (vishing) of IT help-desk staff to reset MFA and gain domain admin access at two major casino/hospitality operators. Caesars paid an extortion demand; MGM refused and suffered roughly ten days of major operational outages across its properties.",
    targetSectors: ["Hospitality", "Gaming"],
    targetCountries: ["United States"],
  },
  {
    name: "Snowflake Customer Instance Extortion Campaign",
    actor: "Scattered Spider",
    status: "CONCLUDED",
    confidence: 70,
    startDate: "2024-04-01",
    endDate: "2024-07-01",
    description:
      "Use of credentials stolen via infostealer malware to access customer instances of the Snowflake cloud data platform that lacked MFA, exfiltrating large volumes of data for extortion. Dozens of organisations were affected, including major retail and telecom brands.",
    targetSectors: ["Technology", "Retail", "Telecommunications"],
    targetCountries: ["United States"],
  },
  {
    name: "UK Retail Sector Ransomware Attacks",
    actor: "Scattered Spider",
    status: "CONCLUDED",
    confidence: 75,
    startDate: "2025-04-01",
    endDate: "2025-06-01",
    description:
      "DragonForce ransomware deployments against major UK retailers via social-engineering of IT help desks, echoing the group's earlier MGM/Caesars playbook. Marks & Spencer suffered a multi-week operational disruption; Co-op and Harrods were also affected.",
    targetSectors: ["Retail"],
    targetCountries: ["United Kingdom"],
  },
  {
    name: "PowerShell Backdoor Campaign Against Diplomatic Missions",
    actor: "APT29",
    status: "CONCLUDED",
    confidence: 82,
    startDate: "2022-01-01",
    endDate: "2022-10-01",
    description:
      "Spearphishing wave against European diplomatic missions delivering an in-memory PowerShell backdoor via HTML smuggling, consistent with APT29's long-running espionage tradecraft against foreign ministries.",
    targetSectors: ["Government"],
    targetCountries: ["European Union", "United States"],
  },
  {
    name: "Operation Ghost Writer / Disinformation-Linked Intrusions",
    actor: "APT28",
    status: "CONCLUDED",
    confidence: 65,
    startDate: "2020-03-01",
    endDate: "2021-06-01",
    description:
      "Website compromises across Eastern Europe used to plant fabricated news content, paired with credential-phishing against military and government personnel in the same target set.",
    targetSectors: ["Government", "Media", "Defense"],
    targetCountries: ["Poland", "Lithuania", "Latvia"],
  },
  {
    name: "AndroxGh0st Cloud Credential Exploitation",
    actor: null,
    status: "ACTIVE",
    confidence: 45,
    startDate: "2023-12-01",
    description:
      "Mass scanning for exposed Laravel `.env` files to harvest AWS, Twilio and SendGrid credentials, then abusing them for further phishing infrastructure and cloud resource abuse. CISA/FBI joint advisory in early 2024; activity assessed to be ongoing under multiple unattributed clusters.",
    targetSectors: ["Technology", "Cloud Hosting"],
    targetCountries: ["Global"],
  },
  {
    name: "CL0P MOVEit Transfer Mass Exploitation",
    actor: null,
    status: "CONCLUDED",
    confidence: 80,
    startDate: "2023-05-27",
    endDate: "2023-09-01",
    description:
      "Zero-day SQL injection in the MOVEit Transfer managed file-transfer product exploited at scale to exfiltrate data from thousands of downstream organisations in a single mass-extortion wave, without deploying ransomware payloads.",
    targetSectors: ["Financial", "Government", "Healthcare", "Professional Services"],
    targetCountries: ["United States", "United Kingdom", "Global"],
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

const REPORTS = [
  {
    title: "Cloud Administrator Credential Harvesting",
    summary:
      "Phishing against cloud administrators followed by OAuth consent abuse. Attribution confidence is deliberately low.",
    body: REPORT_BODY,
    publishedAt: "2026-06-15",
    tlp: "GREEN",
    confidence: 40,
    tags: ["phishing", "cloud", "oauth"],
    actor: null as string | null,
  },
  {
    title: "APT29 Diplomatic Phishing Wave — Q3 Technical Notes",
    summary:
      "In-memory PowerShell backdoor delivered via HTML smuggling against European diplomatic missions; ISO/IMG lure containers bypass Mark-of-the-Web.",
    body: `# Summary

Renewed spearphishing activity against diplomatic and think-tank targets, consistent with prior APT29 tradecraft.

## Delivery

Lure documents impersonate conference invitations from European policy institutes. Delivery relies on ISO/IMG containers to bypass Mark-of-the-Web protections on downloaded attachments.

## Post-compromise

WMI-based persistence and living-off-the-land discovery observed before a lightweight downloader stage deploys.

## Recommendation

Block indicators attached to this report and review mail gateway rules for ISO/IMG attachments from unauthenticated senders.
`,
    publishedAt: "2026-07-18",
    tlp: "AMBER",
    confidence: 85,
    tags: ["phishing", "espionage"],
    actor: "APT29",
  },
  {
    title: "Sandworm Wiper Variant — Technical Analysis",
    summary:
      "Two-stage wiper using a signed driver for kernel access, then targeted MBR and engineering-workstation destruction. TLP:RED.",
    body: `# Summary

Reverse engineering of a newly observed wiper shows a two-stage design: a legitimate signed driver used to gain kernel access, followed by targeted destruction of the MBR and select engineering-workstation file types.

## Attribution notes

The sample shares code-level similarity with prior Industroyer-family tooling but adds anti-forensic timestomping not previously catalogued.

## Handling

TLP:RED — do not redistribute outside the response team without originator approval.
`,
    publishedAt: "2026-07-15",
    tlp: "RED",
    confidence: 90,
    tags: ["wiper", "ics", "destructive"],
    actor: "Sandworm Team",
  },
  {
    title: "Scattered Spider Help-Desk Vishing Playbook",
    summary:
      "Breakdown of observed social-engineering scripts used against IT help desks, including LinkedIn-sourced internal terminology.",
    body: `# Summary

Callers impersonate employees requesting MFA resets, often referencing real internal terminology harvested from prior LinkedIn reconnaissance.

## Recommendation

Adopt a callback-to-verified-number policy for any MFA reset request, and require manager approval for help-desk-initiated credential changes.
`,
    publishedAt: "2026-07-10",
    tlp: "GREEN",
    confidence: 78,
    tags: ["social-engineering", "vishing"],
    actor: "Scattered Spider",
  },
  {
    title: "Quarterly CISA KEV Exploitation Trends",
    summary:
      "Aggregate analysis of CISA KEV additions and observed exploitation velocity. Median time-to-mass-scanning continues to shrink.",
    body: `# Summary

Aggregate analysis of CISA KEV additions and observed exploitation velocity this quarter. Median time from KEV addition to observed mass scanning fell to 4 days, down from 11 days a year ago.

## Trend

Edge and VPN appliances remain the dominant target class, consistent with prior quarters.
`,
    publishedAt: "2026-07-01",
    tlp: "CLEAR",
    confidence: 80,
    tags: ["kev", "trends"],
    actor: null,
  },
] as const;

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

  console.log("\nSeeding reports…");
  for (const r of REPORTS) {
    const report = await db.report.upsert({
      where: { slug: slug(r.title) },
      update: {},
      create: {
        title: r.title,
        slug: slug(r.title),
        summary: r.summary,
        body: r.body,
        published: true,
        publishedAt: new Date(r.publishedAt),
        authorId: admin.id,
        tlp: r.tlp,
        confidence: r.confidence,
        tags: [...r.tags],
      },
    });

    const actorId = r.actor ? actorIds.get(r.actor) : null;
    if (actorId) {
      await db.reportActor.upsert({
        where: { reportId_actorId: { reportId: report.id, actorId } },
        update: {},
        create: { reportId: report.id, actorId, confidence: r.confidence, addedById: admin.id },
      });
    }
  }
  console.log(`  seeded ${REPORTS.length} reports`);

  console.log("\nDone. Sign in and open /actors.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
