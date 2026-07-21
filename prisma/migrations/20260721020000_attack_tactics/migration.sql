-- ATT&CK tactics: add the Tactic model, and make Technique.tactics an array.
--
-- 21% of ATT&CK techniques belong to more than one tactic (T1053.005 spans
-- execution, persistence and privilege-escalation). A scalar column would drop
-- them from every matrix column but one.
--
-- NOTE: `prisma migrate diff` also emitted DROP INDEX for the eight pg_trgm
-- indexes created in 20260721010000_search_indexes. Those are deliberate raw-SQL
-- additions that do not exist in schema.prisma, so Prisma treats them as drift
-- on every diff. They have been removed from this migration — dropping them
-- would silently turn every fuzzy search into a sequential scan.

-- Technique_tactic_idx is dropped legitimately: its column is going away.
DROP INDEX IF EXISTS "Technique_tactic_idx";

-- AlterTable
ALTER TABLE "Technique" DROP COLUMN "tactic",
ADD COLUMN     "tactics" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- CreateTable
CREATE TABLE "Tactic" (
    "id" TEXT NOT NULL,
    "attackId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "shortname" TEXT NOT NULL,
    "description" TEXT,
    "domain" "AttackDomain" NOT NULL DEFAULT 'ENTERPRISE',
    "order" INTEGER NOT NULL,
    "attackVersion" TEXT NOT NULL,

    CONSTRAINT "Tactic_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Tactic_domain_order_idx" ON "Tactic"("domain", "order");

-- CreateIndex
CREATE UNIQUE INDEX "Tactic_shortname_domain_key" ON "Tactic"("shortname", "domain");

-- CreateIndex
CREATE INDEX "Technique_tactics_idx" ON "Technique"("tactics");
