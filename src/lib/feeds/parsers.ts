/**
 * Feed parsers.
 *
 * Pure functions from raw text to structured records — no network, no database,
 * so each format's quirks are handled in one testable place.
 */

export type ParsedNewsItem = {
  title: string;
  url: string;
  summary: string | null;
  publishedAt: Date;
};

export type ParsedVulnerability = {
  cveId: string;
  description: string | null;
  cvssV3?: number | null;
  cvssV4?: number | null;
  epssScore?: number | null;
  knownExploited?: boolean;
  kevDateAdded?: Date | null;
  publishedAt?: Date | null;
  vendorRefs?: string[];
};

// --- RSS / Atom -----------------------------------------------------------

/**
 * Deliberately regex-based rather than a full XML parser.
 *
 * Vendor security blogs emit by turns RSS 2.0, Atom, and malformed hybrids;
 * a strict parser throws on the malformed ones and we lose the feed entirely.
 * Extracting the four fields we actually use is more robust here, and the cost
 * of a mis-parse is one skipped item rather than a dead source.
 */
export function parseRss(xml: string): ParsedNewsItem[] {
  const items: ParsedNewsItem[] = [];

  // <item> is RSS, <entry> is Atom.
  const blocks = xml.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) ?? [];

  for (const block of blocks) {
    const title = decodeXml(pick(block, "title"));
    if (!title) continue;

    // Atom puts the URL in <link href="...">; RSS puts it in the element body.
    const url =
      block.match(/<link[^>]*\shref=["']([^"']+)["']/i)?.[1] ??
      decodeXml(pick(block, "link")) ??
      decodeXml(pick(block, "guid"));
    if (!url || !/^https?:\/\//i.test(url)) continue;

    const rawDate =
      pick(block, "pubDate") ??
      pick(block, "published") ??
      pick(block, "updated") ??
      pick(block, "dc:date");
    const parsed = rawDate ? new Date(rawDate) : null;
    const publishedAt =
      parsed && !Number.isNaN(parsed.getTime()) ? parsed : new Date();

    const summaryRaw =
      pick(block, "description") ??
      pick(block, "summary") ??
      pick(block, "content");

    items.push({
      title: title.slice(0, 500),
      url,
      summary: summaryRaw ? stripHtml(decodeXml(summaryRaw) ?? "").slice(0, 1000) : null,
      publishedAt,
    });
  }

  return items;
}

function pick(block: string, tag: string): string | null {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "i");
  const m = block.match(re);
  if (!m) return null;
  return stripCdata(m[1]).trim() || null;
}

function stripCdata(s: string): string {
  return s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
}

function stripHtml(s: string): string {
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function decodeXml(s: string | null): string | null {
  if (s === null) return null;
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&nbsp;/g, " ")
    // Ampersand last, or it would corrupt the entities above.
    .replace(/&amp;/g, "&")
    .trim();
}

// --- CSV ------------------------------------------------------------------

/**
 * RFC 4180-ish CSV: handles quoted fields, embedded commas, doubled quotes and
 * embedded newlines. abuse.ch feeds ship comment preambles starting with '#'.
 */
export function parseCsv(text: string): Record<string, string>[] {
  // Strip a UTF-8 BOM. Several abuse.ch and EPSS files ship one; without this
  // the first header cell is "\uFEFFurl", so `r.url` lookups silently return
  // empty and the whole feed ingests nothing while reporting "ok".
  const rows = splitCsvRows(text.replace(/^\uFEFF/, ""));
  const dataRows = rows.filter(
    (r) => r.length > 0 && !(r[0] ?? "").trimStart().startsWith("#"),
  );
  if (dataRows.length < 2) return [];

  const header = dataRows[0].map((h) => h.trim().replace(/^"|"$/g, ""));
  return dataRows.slice(1).map((row) => {
    const obj: Record<string, string> = {};
    header.forEach((key, i) => {
      obj[key] = (row[i] ?? "").trim();
    });
    return obj;
  });
}

function splitCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
      continue;
    }

    if (c === '"') inQuotes = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (c !== "\r") {
      field += c;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

// --- CISA KEV -------------------------------------------------------------

export function parseKev(json: unknown): ParsedVulnerability[] {
  const body = json as {
    vulnerabilities?: {
      cveID?: string;
      vulnerabilityName?: string;
      shortDescription?: string;
      dateAdded?: string;
      notes?: string;
    }[];
  };

  return (body.vulnerabilities ?? [])
    .filter((v) => v.cveID)
    .map((v) => ({
      cveId: v.cveID!.toUpperCase(),
      description: v.shortDescription ?? v.vulnerabilityName ?? null,
      knownExploited: true,
      kevDateAdded: v.dateAdded ? new Date(v.dateAdded) : null,
      vendorRefs: v.notes
        ? v.notes.split(/[;\s]+/).filter((s) => /^https?:\/\//.test(s))
        : [],
    }));
}

// --- EPSS -----------------------------------------------------------------

/** EPSS ships CSV with a '#model_version' preamble. */
export function parseEpss(csv: string): { cveId: string; epssScore: number }[] {
  return parseCsv(csv)
    .map((r) => ({
      cveId: (r.cve ?? "").toUpperCase(),
      epssScore: Number(r.epss ?? NaN),
    }))
    .filter((r) => /^CVE-\d{4}-\d+$/.test(r.cveId) && Number.isFinite(r.epssScore));
}

// --- NVD 2.0 --------------------------------------------------------------

export function parseNvd(json: unknown): ParsedVulnerability[] {
  const body = json as {
    vulnerabilities?: {
      cve?: {
        id?: string;
        published?: string;
        descriptions?: { lang?: string; value?: string }[];
        metrics?: {
          cvssMetricV40?: { cvssData?: { baseScore?: number } }[];
          cvssMetricV31?: { cvssData?: { baseScore?: number } }[];
          cvssMetricV30?: { cvssData?: { baseScore?: number } }[];
        };
        references?: { url?: string }[];
      };
    }[];
  };

  return (body.vulnerabilities ?? [])
    .map((entry) => entry.cve)
    .filter((cve): cve is NonNullable<typeof cve> => Boolean(cve?.id))
    .map((cve) => {
      const m = cve.metrics ?? {};
      const v3 =
        m.cvssMetricV31?.[0]?.cvssData?.baseScore ??
        m.cvssMetricV30?.[0]?.cvssData?.baseScore ??
        null;
      const v4 = m.cvssMetricV40?.[0]?.cvssData?.baseScore ?? null;

      const english =
        cve.descriptions?.find((d) => d.lang === "en")?.value ??
        cve.descriptions?.[0]?.value ??
        null;

      return {
        cveId: cve.id!.toUpperCase(),
        description: english,
        cvssV3: v3,
        cvssV4: v4,
        publishedAt: cve.published ? new Date(cve.published) : null,
        vendorRefs: (cve.references ?? [])
          .map((r) => r.url)
          .filter((u): u is string => Boolean(u))
          .slice(0, 10),
      };
    });
}
