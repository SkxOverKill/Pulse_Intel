import type { SourceType, Tlp } from "@/generated/prisma/enums";

/**
 * Preconfigured free intelligence sources.
 *
 * All are public and free — no key required beyond the OTX one we already hold.
 * `handler` selects the ingest routine in src/lib/feeds/run.ts.
 *
 * `defaultConfidence` encodes how much to trust each source. CISA KEV is
 * authoritative about active exploitation (95); a vendor blog is useful context
 * but not machine-actionable (40). `decayHalfLifeDays` reflects how fast the
 * indicator type goes stale — IPs rotate in weeks, file hashes never do.
 */

export type FeedHandler =
  | "kev"
  | "epss"
  | "nvd-recent"
  | "urlhaus"
  | "threatfox"
  | "feodo"
  | "otx-pulses"
  | "rss-news";

export type CatalogSource = {
  name: string;
  type: SourceType;
  url: string;
  handler: FeedHandler;
  schedule: string;
  defaultConfidence: number;
  defaultTlp: Tlp;
  decayHalfLifeDays: number | null;
  description: string;
};

export const FEED_CATALOG: CatalogSource[] = [
  // --- Vulnerabilities ----------------------------------------------------
  {
    name: "CISA Known Exploited Vulnerabilities",
    type: "JSON",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    handler: "kev",
    schedule: "0 * * * *",
    defaultConfidence: 95,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description:
      "US government catalogue of vulnerabilities with confirmed active exploitation. The single highest-signal vulnerability feed available.",
  },
  {
    name: "FIRST EPSS Scores",
    type: "CSV",
    url: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    handler: "epss",
    schedule: "0 3 * * *",
    defaultConfidence: 80,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description:
      "Exploit Prediction Scoring System: probability a CVE will be exploited in the next 30 days.",
  },
  {
    name: "NVD Recent CVEs",
    type: "JSON",
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0",
    handler: "nvd-recent",
    schedule: "30 * * * *",
    defaultConfidence: 90,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Newly published CVEs with CVSS scoring from NIST.",
  },

  // --- Indicators ---------------------------------------------------------
  {
    name: "abuse.ch URLhaus",
    type: "CSV",
    url: "https://urlhaus.abuse.ch/downloads/csv_recent/",
    handler: "urlhaus",
    schedule: "0 * * * *",
    defaultConfidence: 75,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: 30,
    description: "Recent malware distribution URLs.",
  },
  {
    name: "abuse.ch ThreatFox",
    type: "JSON",
    url: "https://threatfox.abuse.ch/export/json/recent/",
    handler: "threatfox",
    schedule: "0 * * * *",
    defaultConfidence: 75,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: 30,
    description: "Recent IOCs associated with named malware families.",
  },
  {
    name: "abuse.ch Feodo Tracker",
    type: "JSON",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    handler: "feodo",
    schedule: "0 * * * *",
    defaultConfidence: 85,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: 14,
    description: "Botnet command-and-control servers (Dridex, Emotet, TrickBot, QakBot).",
  },
  {
    name: "AlienVault OTX Subscribed Pulses",
    type: "JSON",
    url: "https://otx.alienvault.com/api/v1/pulses/subscribed",
    handler: "otx-pulses",
    schedule: "15 * * * *",
    defaultConfidence: 60,
    defaultTlp: "GREEN",
    decayHalfLifeDays: 60,
    description:
      "Community threat reports and their indicators. Requires the OTX API key.",
  },

  // --- News ---------------------------------------------------------------
  // Confidence is low across the board: these are context for analysts, not
  // machine-actionable intelligence.
  {
    name: "CISA Cybersecurity Advisories",
    type: "RSS",
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 90,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Official US government cybersecurity advisories.",
  },
  {
    name: "The Hacker News",
    type: "RSS",
    url: "https://feeds.feedburner.com/TheHackersNews",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 40,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "General security news.",
  },
  {
    name: "BleepingComputer",
    type: "RSS",
    url: "https://www.bleepingcomputer.com/feed/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 45,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Breach, ransomware and malware reporting.",
  },
  {
    name: "Google Threat Intelligence (Mandiant)",
    type: "RSS",
    url: "https://cloud.google.com/blog/topics/threat-intelligence/rss",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 70,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Mandiant incident response and APT research.",
  },
  {
    name: "Microsoft Security Blog",
    type: "RSS",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 70,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "MSTIC threat actor research and detections.",
  },
  {
    name: "Cisco Talos Intelligence",
    type: "RSS",
    url: "https://blog.talosintelligence.com/rss/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 70,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Talos malware and campaign analysis.",
  },
  {
    name: "Unit 42 (Palo Alto Networks)",
    type: "RSS",
    url: "https://unit42.paloaltonetworks.com/feed/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 70,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Unit 42 threat research.",
  },
  {
    name: "The DFIR Report",
    type: "RSS",
    url: "https://thedfirreport.com/feed/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 75,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Detailed intrusion walk-throughs with TTPs and IOCs.",
  },
  {
    name: "Securelist (Kaspersky)",
    type: "RSS",
    url: "https://securelist.com/feed/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 65,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "APT campaign research.",
  },
  {
    name: "Check Point Research",
    type: "RSS",
    url: "https://research.checkpoint.com/feed/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 70,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description:
      "Check Point Research APT and campaign analysis. WordPress feed with no rate limits, but two quirks: summaries are HTML-wrapped in CDATA (with numeric entities like &#8230;) and guids are isPermaLink=\"false\", so article links must come from <link>, never <guid>.",
  },
  {
    name: "Krebs on Security",
    type: "RSS",
    url: "https://krebsonsecurity.com/feed/",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 45,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Investigative cybercrime reporting.",
  },
  {
    name: "SANS Internet Storm Center",
    type: "RSS",
    url: "https://isc.sans.edu/rssfeed_full.xml",
    handler: "rss-news",
    schedule: "0 * * * *",
    defaultConfidence: 60,
    defaultTlp: "CLEAR",
    decayHalfLifeDays: null,
    description: "Daily handler diaries on emerging activity.",
  },
];

export function findCatalogSource(name: string): CatalogSource | undefined {
  return FEED_CATALOG.find((s) => s.name === name);
}
