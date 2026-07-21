import type { IndicatorType } from "@/generated/prisma/enums";
import type { EnrichmentProvider } from "@/lib/enrichment/types";
import { abuseIpDbProvider } from "@/lib/enrichment/providers/abuseipdb";
import { otxProvider } from "@/lib/enrichment/providers/otx";
import { stubProvider } from "@/lib/enrichment/providers/stub";
import { virusTotalProvider } from "@/lib/enrichment/providers/virustotal";

/**
 * Provider order matters and is not alphabetical.
 *
 * OTX is effectively unlimited, so it goes first — every indicator it can answer
 * is a VirusTotal request preserved. AbuseIPDB (1,000/day) next. VirusTotal
 * last, because at 4/min and 500/day it is the scarcest resource in the system
 * and should only be spent on indicators the cheaper providers could not cover.
 */
export const PROVIDERS: EnrichmentProvider[] = [
  otxProvider,
  abuseIpDbProvider,
  virusTotalProvider,
  stubProvider,
];

export function getProvider(name: string): EnrichmentProvider | undefined {
  return PROVIDERS.find((p) => p.name === name);
}

/** Configured providers that can say something about this indicator type. */
export function providersFor(type: IndicatorType): EnrichmentProvider[] {
  return PROVIDERS.filter((p) => p.isConfigured() && p.supports(type));
}

export function configuredProviders(): EnrichmentProvider[] {
  return PROVIDERS.filter((p) => p.isConfigured());
}
