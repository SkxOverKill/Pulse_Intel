export function indicatorExpiresAt(
  seenAt: Date,
  decayHalfLifeDays: number | null | undefined,
): Date | null {
  if (!decayHalfLifeDays || decayHalfLifeDays <= 0) return null;
  return new Date(seenAt.getTime() + decayHalfLifeDays * 86_400_000);
}

export function activeIndicatorWhere(now = new Date()) {
  return {
    OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
  };
}
