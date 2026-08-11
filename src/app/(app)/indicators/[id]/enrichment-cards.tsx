"use client";

/**
 * Provider-specific enrichment card renderers.
 *
 * The raw JSON stored in Enrichment.rawResponse is rich — GreyNoise has
 * classification + tags, Shodan has port lists and CVEs — but the generic
 * table on the indicator page just showed "provider / verdict / score / dates".
 * These cards make that data readable for an analyst without making them
 * open a browser tab to the provider's own UI.
 *
 * Each renderer receives the full rawResponse JSON and renders what it knows.
 * Unknown providers fall through to the generic card.
 */

import { AlertTriangle, CheckCircle2, HelpCircle, Shield, XCircle } from "lucide-react";

type Verdict = "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN";

type EnrichmentRow = {
  id: string;
  provider: string;
  verdict: Verdict;
  score: number | null;
  rawResponse: unknown;
  fetchedAt: Date;
  expiresAt: Date;
  error: string | null;
};

// --------------------------------------------------------------------------
// Shared verdict badge
// --------------------------------------------------------------------------

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const map: Record<Verdict, { label: string; className: string; Icon: typeof CheckCircle2 }> = {
    MALICIOUS:  { label: "Malicious",  className: "text-danger bg-danger/10 border-danger/30",  Icon: XCircle },
    SUSPICIOUS: { label: "Suspicious", className: "text-warn bg-warn/10 border-warn/30",         Icon: AlertTriangle },
    BENIGN:     { label: "Benign",     className: "text-ok bg-ok/10 border-ok/30",               Icon: CheckCircle2 },
    UNKNOWN:    { label: "Unknown",    className: "text-ink-muted bg-surface-2 border-line",      Icon: HelpCircle },
  };
  const { label, className, Icon } = map[verdict] ?? map.UNKNOWN;
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-semibold ${className}`}>
      <Icon className="size-3" />
      {label}
    </span>
  );
}

function ScorePill({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-ink-faint">—</span>;
  const color =
    score >= 70 ? "text-danger" :
    score >= 30 ? "text-warn" :
    "text-ok";
  return <span className={`tabular text-xs font-bold ${color}`}>{score}</span>;
}

// --------------------------------------------------------------------------
// GreyNoise card
// --------------------------------------------------------------------------

type GnCommunity = {
  ip?: string;
  noise?: boolean;
  riot?: boolean;
  classification?: string;
  name?: string;
  link?: string;
  last_seen?: string;
  message?: string;
};

function GreyNoiseCard({ row }: { row: EnrichmentRow }) {
  const raw = row.rawResponse as GnCommunity;
  if ((row.rawResponse as { notInDataset?: boolean }).notInDataset) {
    return (
      <ProviderCard row={row} label="GreyNoise">
        <p className="text-xs text-ink-muted">
          Not in GreyNoise dataset — IP has never been observed mass-scanning the internet.
          This absence is a mild positive signal (not a known noisy scanner).
        </p>
      </ProviderCard>
    );
  }

  return (
    <ProviderCard row={row} label="GreyNoise">
      <div className="space-y-2">
        {raw.riot ? (
          <div className="flex items-start gap-2 rounded border border-ok/30 bg-ok/8 px-2.5 py-2 text-xs text-ok">
            <Shield className="mt-px size-3.5 shrink-0" />
            <span>
              <strong>RIOT</strong> — known benign infrastructure.
              {raw.name ? ` Identified as: ${raw.name}.` : ""}
              This IP belongs to trusted internet infrastructure (CDN, DNS, cloud provider).
            </span>
          </div>
        ) : null}

        {!raw.riot && raw.noise ? (
          <div className="rounded border border-warn/30 bg-warn/8 px-2.5 py-2 text-xs text-warn">
            <strong>Noise</strong> — this IP is actively scanning the internet (mass scanner, not targeted).
            {raw.name ? ` Identified scanner: ${raw.name}.` : ""}
          </div>
        ) : null}

        {!raw.riot && !raw.noise ? (
          <div className="rounded border border-line bg-surface-2 px-2.5 py-2 text-xs text-ink-muted">
            <strong>Not noise</strong> — this IP is <em>not</em> in GreyNoise&apos;s mass-scanner dataset.
            Unknown IPs communicating with you are more suspicious than known scanners.
          </div>
        ) : null}

        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          <span className="text-ink-muted">Classification</span>
          <span className="font-medium capitalize">{raw.classification ?? "—"}</span>
          {raw.name ? (
            <>
              <span className="text-ink-muted">Known as</span>
              <span>{raw.name}</span>
            </>
          ) : null}
          {raw.last_seen ? (
            <>
              <span className="text-ink-muted">Last seen</span>
              <span className="tabular">{raw.last_seen.slice(0, 10)}</span>
            </>
          ) : null}
        </div>

        {raw.link ? (
          <a
            href={raw.link}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-text text-[11px] text-brand hover:underline"
          >
            View on GreyNoise →
          </a>
        ) : null}
      </div>
    </ProviderCard>
  );
}

// --------------------------------------------------------------------------
// Shodan card
// --------------------------------------------------------------------------

type ShodanInternetDb = {
  ports?: number[];
  cpes?: string[];
  vulns?: string[];
  hostnames?: string[];
  tags?: string[];
  notIndexed?: boolean;
};

type ShodanFull = {
  ports?: number[];
  vulns?: Record<string, { cvss?: number; summary?: string }>;
  tags?: string[];
  org?: string;
  asn?: string;
  country_name?: string;
  city?: string;
  isp?: string;
  hostnames?: string[];
};

function ShodanCard({ row }: { row: EnrichmentRow }) {
  const raw = row.rawResponse as ShodanInternetDb & ShodanFull;

  if (raw.notIndexed) {
    return (
      <ProviderCard row={row} label="Shodan">
        <p className="text-xs text-ink-muted">
          Not indexed by Shodan — no open ports found on this IP.
        </p>
      </ProviderCard>
    );
  }

  const ports      = raw.ports ?? [];
  const vulns      = raw.vulns ?? [];
  const fullVulns  = typeof vulns === "object" && !Array.isArray(vulns)
    ? Object.entries(vulns as Record<string, { cvss?: number; summary?: string }>)
    : [];
  const cveList    = Array.isArray(vulns)
    ? (vulns as string[])
    : fullVulns.map(([k]) => k);
  const tags       = raw.tags ?? [];
  const hostnames  = raw.hostnames ?? [];

  return (
    <ProviderCard row={row} label="Shodan">
      <div className="space-y-2.5">
        {/* Org / geo */}
        {(raw.org || raw.country_name) ? (
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
            {raw.org ? (
              <>
                <span className="text-ink-muted">Organization</span>
                <span>{raw.org}</span>
              </>
            ) : null}
            {raw.asn ? (
              <>
                <span className="text-ink-muted">ASN</span>
                <span className="font-mono">{raw.asn}</span>
              </>
            ) : null}
            {raw.country_name ? (
              <>
                <span className="text-ink-muted">Country</span>
                <span>{raw.country_name}{raw.city ? `, ${raw.city}` : ""}</span>
              </>
            ) : null}
            {raw.isp ? (
              <>
                <span className="text-ink-muted">ISP</span>
                <span>{raw.isp}</span>
              </>
            ) : null}
          </div>
        ) : null}

        {/* Ports */}
        {ports.length > 0 ? (
          <div>
            <p className="mb-1 text-[11px] font-medium text-ink-muted">
              Open ports ({ports.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {ports.slice(0, 30).map((p) => (
                <span
                  key={p}
                  className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-ink"
                >
                  {p}
                </span>
              ))}
              {ports.length > 30 ? (
                <span className="text-[11px] text-ink-faint">
                  +{ports.length - 30} more
                </span>
              ) : null}
            </div>
          </div>
        ) : null}

        {/* CVEs */}
        {cveList.length > 0 ? (
          <div>
            <p className="mb-1 text-[11px] font-medium text-danger">
              Vulnerabilities ({cveList.length})
            </p>
            <div className="space-y-1">
              {cveList.slice(0, 8).map((cve) => {
                const detail = fullVulns.find(([k]) => k === cve)?.[1];
                return (
                  <div key={cve} className="flex items-start gap-2 text-xs">
                    <a
                      href={`/vulnerabilities?q=${cve}`}
                      className="shrink-0 font-mono text-danger hover:underline"
                    >
                      {cve}
                    </a>
                    {detail?.cvss ? (
                      <span className="text-ink-muted">CVSS {detail.cvss.toFixed(1)}</span>
                    ) : null}
                    {detail?.summary ? (
                      <span className="truncate text-ink-muted">{detail.summary}</span>
                    ) : null}
                  </div>
                );
              })}
              {cveList.length > 8 ? (
                <p className="text-[11px] text-ink-faint">+{cveList.length - 8} more</p>
              ) : null}
            </div>
          </div>
        ) : null}

        {/* Tags */}
        {tags.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {tags.map((t: string) => (
              <span
                key={t}
                className="rounded border border-line bg-surface-2 px-2 py-0.5 text-[11px] text-ink-muted"
              >
                {t}
              </span>
            ))}
          </div>
        ) : null}

        {/* Hostnames */}
        {hostnames.length > 0 ? (
          <div>
            <p className="mb-1 text-[11px] font-medium text-ink-muted">Hostnames</p>
            <div className="space-y-0.5">
              {hostnames.slice(0, 5).map((h: string) => (
                <p key={h} className="font-mono text-[11px] text-ink">{h}</p>
              ))}
            </div>
          </div>
        ) : null}

        <a
          href={`https://www.shodan.io/host/${(row.rawResponse as { ip_str?: string; ip?: string }).ip_str ?? (row.rawResponse as { ip?: string }).ip ?? ""}`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-text text-[11px] text-brand hover:underline"
        >
          View on Shodan →
        </a>
      </div>
    </ProviderCard>
  );
}

// --------------------------------------------------------------------------
// Generic card (for all other providers)
// --------------------------------------------------------------------------

function GenericCard({ row }: { row: EnrichmentRow }) {
  return (
    <ProviderCard row={row} label={row.provider}>
      {row.error ? (
        <p className="text-xs text-danger">{row.error}</p>
      ) : (
        <p className="text-xs text-ink-muted">
          No detailed view available for this provider.
        </p>
      )}
    </ProviderCard>
  );
}

// --------------------------------------------------------------------------
// Card shell
// --------------------------------------------------------------------------

function ProviderCard({
  row,
  label,
  children,
}: {
  row: EnrichmentRow;
  label: string;
  children: React.ReactNode;
}) {
  const now = new Date();
  const fresh = row.expiresAt > now;

  return (
    <div className="rounded-[--radius-card] border border-line bg-surface p-4">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-ink capitalize">{label}</span>
          <VerdictBadge verdict={row.verdict} />
          <ScorePill score={row.score} />
        </div>
        <div className="text-right text-[11px] text-ink-faint">
          <div>{row.fetchedAt.toISOString().slice(0, 10)}</div>
          <div className={fresh ? "text-ok" : "text-warn"}>
            {fresh ? "fresh" : "stale"}
          </div>
        </div>
      </div>
      {children}
    </div>
  );
}

// --------------------------------------------------------------------------
// Main export — dispatcher
// --------------------------------------------------------------------------

export function EnrichmentCards({ enrichments }: { enrichments: EnrichmentRow[] }) {
  if (enrichments.length === 0) return null;

  return (
    <div className="space-y-3">
      {enrichments.map((e) => {
        switch (e.provider) {
          case "greynoise": return <GreyNoiseCard key={e.id} row={e} />;
          case "shodan":    return <ShodanCard    key={e.id} row={e} />;
          default:          return <GenericCard   key={e.id} row={e} />;
        }
      })}
    </div>
  );
}
