-- Hand-authored: `prisma migrate diff` also emitted DROP INDEX for the 8 raw-SQL
-- trigram indexes (they live in 20260721010000_search_indexes, not schema.prisma,
-- so every diff sees them as drift). Those DROPs are deliberately omitted here —
-- applying them would silently turn fuzzy search into sequential scans. See
-- HANDOVER.md §4.2 and scripts/migrate-offline.ts.

-- CreateTable
CREATE TABLE "HuntAlert" (
    "id" TEXT NOT NULL,
    "huntId" TEXT NOT NULL,
    "matchCount" INTEGER NOT NULL,
    "newCount" INTEGER NOT NULL,
    "indicatorIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "acknowledged" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "HuntAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "HuntAlert_huntId_idx" ON "HuntAlert"("huntId");

-- CreateIndex
CREATE INDEX "HuntAlert_acknowledged_idx" ON "HuntAlert"("acknowledged");

-- AddForeignKey
ALTER TABLE "HuntAlert" ADD CONSTRAINT "HuntAlert_huntId_fkey" FOREIGN KEY ("huntId") REFERENCES "HuntQuery"("id") ON DELETE CASCADE ON UPDATE CASCADE;
