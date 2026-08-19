/**
 * Indicator-confidence reconciliation.
 *
 * Enrichment combines provider scores into one number; analysts sometimes set
 * (or import) a confidence of their own. The rule is deliberately simple:
 *   - an analyst-locked confidence is sacred — no provider score changes it;
 *   - otherwise the max provider score wins (one provider seeing something
 *     malicious is signal, and averaging it flat with three "unknown"s buries
 *     detections — see recomputeIndicatorConfidence in enrich.ts).
 *
 * Pure, so it is unit-testable without a database.
 */
export function pickIndicatorConfidence(
  current: number,
  locked: boolean,
  providerScores: number[],
): number {
  if (locked || providerScores.length === 0) return current;
  return Math.max(...providerScores);
}