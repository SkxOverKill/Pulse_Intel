import * as cheerio from "cheerio";

/**
 * Fetches a source article's page and extracts its main body text.
 *
 * This is a per-item, analyst-triggered action (not run automatically at feed
 * ingest time) — deliberately: it copies a third party's copyrighted article
 * text onto this site, which is a real legal/ToS consideration the product
 * owner accepted knowingly, not something to do silently for every ingested
 * item. Always keep the original source link and attribution alongside the
 * extracted text (see the news detail page) rather than presenting it as if
 * it were our own writing.
 *
 * Heuristic extraction, not a full Readability port: strip obvious
 * boilerplate (nav/header/footer/script/style/aside/forms), then pick the
 * element with the most cumulative paragraph text — usually the article body
 * on a vendor blog or news site — and return its paragraphs as plain text.
 * Good enough for security-vendor blogs and news outlets, which are
 * paragraph-heavy and not JS-rendered SPAs; won't work for sites that render
 * content client-side.
 */
export async function fetchFullArticle(url: string): Promise<string | null> {
  const res = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; PulseIntelligence/1.0)" },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) return null;

  const html = await res.text();
  const $ = cheerio.load(html);

  $("script, style, nav, header, footer, aside, form, iframe, noscript").remove();

  let best: { el: ReturnType<typeof $>; length: number } | null = null;
  $("article, main, div, section").each((_, el) => {
    const node = $(el);
    const text = node.find("p").text();
    if (text.length > (best?.length ?? 0)) {
      best = { el: node, length: text.length };
    }
  });

  const container = best ? (best as { el: ReturnType<typeof $> }).el : $("body");
  const paragraphs = container
    .find("p")
    .map((_, p) => $(p).text().trim())
    .get()
    .filter((p) => p.length > 0);

  if (paragraphs.length === 0) return null;

  return paragraphs.join("\n\n");
}
