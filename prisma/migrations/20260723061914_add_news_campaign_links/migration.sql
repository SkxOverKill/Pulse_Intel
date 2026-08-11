-- Hand-authored: `prisma migrate diff` also emitted DROP INDEX for the 8 raw-SQL
-- trigram indexes (they live in 20260721010000_search_indexes, not schema.prisma,
-- so every diff sees them as drift). Those DROPs are deliberately omitted here —
-- applying them would silently turn fuzzy search into sequential scans. See
-- HANDOVER.md §4.2 and scripts/migrate-offline.ts.

-- AlterTable
ALTER TABLE "NewsItem" ADD COLUMN     "linkedCampaignIds" TEXT[] DEFAULT ARRAY[]::TEXT[];
