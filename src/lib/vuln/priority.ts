/**
 * Vulnerability priority scoring — a single 0-100 number that answers
 * "how urgently should this be patched?" faster than reading CVSS + EPSS
 * side-by-side.
 *
 * The formula follows CISA's Stakeholder-Specific Vulnerability Categorization
 * (SSVC) philosophy: being actively exploited (KEV) is categorically more
 * urgent than any CVSS score, and exploit probability (EPSS) is a better
 * predictor of near-term exploitation than severity alone.
 *
 * Tiers (maps to a label + color token for the UI):
 *   CRITICAL  90-100  KEV + critical CVSS, or EPSS ≥ 0.5
 *   HIGH      70-89   High CVSS + meaningful EPSS, or KEV alone
 *   MEDIUM    40-69   Moderate scores without active exploitation
 *   LOW        0-39   Low-severity, low exploit probability
 *
 * Design notes:
 *   - KEV status adds 30 points directly. Nothing else does that.
 *   - EPSS (0-1) contributes up to 40 points via a square-root curve that
 *     rewards high-probability vulns without requiring 100% to matter.
 *   - CVSS (0-10) contributes up to 30 points linearly (CVSS/10 * 30).
 *   - Total is capped at 100. KEV-alone gives 30; with high CVSS = 60;
 *     with high EPSS = 100 (rounding to CRITICAL, as it should).
 */

export type PriorityTier = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type PriorityResult = {
  score: number;        // 0-100
  tier: PriorityTier;
  label: string;        // human-readable, matches tier
  reasoning: string;   // one-liner for the UI tooltip
};

export function computePriority(
  cvss: number | null,
  epss: number | null,
  knownExploited: boolean,
): PriorityResult {
  let score = 0;
  const parts: string[] = [];

  // KEV: +30 points, hard floor. The CISA mandate is clear.
  if (knownExploited) {
    score += 30;
    parts.push("CISA KEV");
  }

  // EPSS: square-root curve → up to 40 points.
  // sqrt(epss) is gentler than linear — a 1% EPSS still contributes ~6 pts
  // (low probability but real signal), while 50% gives 28 pts and 100% gives 40.
  if (epss !== null && epss > 0) {
    const epssContrib = Math.round(Math.sqrt(epss) * 40);
    score += epssContrib;
    parts.push(`EPSS ${(epss * 100).toFixed(1)}%`);
  }

  // CVSS: linear, up to 30 points.
  const cvssBase = cvss ?? 0;
  if (cvssBase > 0) {
    const cvssContrib = Math.round((cvssBase / 10) * 30);
    score += cvssContrib;
    parts.push(`CVSS ${cvssBase.toFixed(1)}`);
  }

  score = Math.min(100, Math.max(0, score));

  let tier: PriorityTier;
  if (score >= 90)      tier = "CRITICAL";
  else if (score >= 70) tier = "HIGH";
  else if (score >= 40) tier = "MEDIUM";
  else                  tier = "LOW";

  const reasoning =
    parts.length > 0
      ? parts.join(" · ")
      : "Insufficient scoring data";

  return {
    score,
    tier,
    label: tier.charAt(0) + tier.slice(1).toLowerCase(),
    reasoning,
  };
}

export const PRIORITY_COLORS: Record<PriorityTier, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "bg-sev-critical/10", text: "text-sev-critical", border: "border-sev-critical/30" },
  HIGH:     { bg: "bg-sev-high/10",     text: "text-sev-high",     border: "border-sev-high/30" },
  MEDIUM:   { bg: "bg-sev-medium/10",   text: "text-sev-medium",   border: "border-sev-medium/30" },
  LOW:      { bg: "bg-sev-low/10",      text: "text-sev-low",      border: "border-sev-low/30" },
};
