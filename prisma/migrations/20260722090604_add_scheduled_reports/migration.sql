-- Hand-authored: `prisma migrate diff` also emitted DROP INDEX for the 8 raw-SQL
-- trigram indexes (they live in 20260721010000_search_indexes, not schema.prisma,
-- so every diff sees them as drift). Those DROPs are deliberately omitted here —
-- applying them would silently turn fuzzy search into sequential scans. See
-- HANDOVER.md §4.2 and scripts/migrate-offline.ts.

-- CreateTable
CREATE TABLE "ScheduledReport" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "schedule" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastRunAt" TIMESTAMP(3),
    "ownerId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScheduledReport_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ScheduledReport_ownerId_idx" ON "ScheduledReport"("ownerId");

-- AddForeignKey
ALTER TABLE "ScheduledReport" ADD CONSTRAINT "ScheduledReport_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
