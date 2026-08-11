/// Flattens each provider's raw JSON response into the handful of fields an
/// analyst actually wants to see in a table — location/ISP/reputation, not
/// the full nested payload. Kept separate from the provider modules
/// themselves so `rawResponse` (already persisted verbatim in `Enrichment`)
/// stays the source of truth and this is purely a display concern.
export type DetailValue = string | number | boolean | null;

function num(v: unknown): number | null {
  return typeof v === "number" ? v : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

export function extractDetails(
  providerName: string,
  raw: unknown,
): Record<string, DetailValue> {
  if (!raw || typeof raw !== "object") return {};

  if (providerName === "abuseipdb") {
    const data = (raw as { data?: Record<string, unknown> }).data;
    if (!data) return {};
    return {
      country: str(data.countryCode),
      isp: str(data.isp),
      domain: str(data.domain),
      usageType: str(data.usageType),
      isWhitelisted: typeof data.isWhitelisted === "boolean" ? data.isWhitelisted : null,
      totalReports: num(data.totalReports),
      distinctReporters: num(data.numDistinctUsers),
      lastReportedAt: str(data.lastReportedAt),
    };
  }

  if (providerName === "virustotal") {
    const attrs = (raw as { data?: { attributes?: Record<string, unknown> } }).data?.attributes;
    if (!attrs) return {};
    const stats = (attrs.last_analysis_stats ?? {}) as Record<string, unknown>;
    const votes = (attrs.total_votes ?? {}) as Record<string, unknown>;
    const categories = attrs.categories;
    return {
      country: str(attrs.country),
      asOwner: str(attrs.as_owner),
      asn: num(attrs.asn),
      reputation: num(attrs.reputation),
      maliciousEngines: num(stats.malicious),
      suspiciousEngines: num(stats.suspicious),
      harmlessEngines: num(stats.harmless),
      undetectedEngines: num(stats.undetected),
      communityMalicious: num(votes.malicious),
      communityHarmless: num(votes.harmless),
      categories:
        categories && typeof categories === "object"
          ? Object.values(categories as Record<string, unknown>).join(", ") || null
          : null,
    };
  }

  if (providerName === "otx") {
    const pulseInfo = (raw as { pulse_info?: Record<string, unknown> }).pulse_info;
    const rawObj = raw as Record<string, unknown>;
    return {
      country: str(rawObj.country_name) ?? str(rawObj.country_code),
      asn: str(rawObj.asn),
      pulseCount: pulseInfo && typeof pulseInfo === "object" ? num(pulseInfo.count) : null,
    };
  }

  return {};
}
