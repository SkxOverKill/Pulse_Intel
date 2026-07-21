-- Pulse Intelligence: initial schema.
--
-- Extensions are created here so later phases can add trigram / full-text
-- indexes without a separate privileged step. Search indexes themselves land
-- in Phase 2 alongside the search implementation.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('ADMIN', 'ANALYST', 'READONLY');

-- CreateEnum
CREATE TYPE "Tlp" AS ENUM ('CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED');

-- CreateEnum
CREATE TYPE "IndicatorType" AS ENUM ('IPV4', 'IPV6', 'DOMAIN', 'URL', 'MD5', 'SHA1', 'SHA256', 'EMAIL', 'CVE', 'BTC_ADDRESS', 'REGISTRY_KEY', 'MUTEX', 'FILENAME', 'USER_AGENT', 'ASN');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "Motivation" AS ENUM ('ESPIONAGE', 'FINANCIAL', 'HACKTIVISM', 'DESTRUCTION', 'INFORMATION_OPS', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "Sophistication" AS ENUM ('MINIMAL', 'INTERMEDIATE', 'ADVANCED', 'EXPERT', 'STRATEGIC');

-- CreateEnum
CREATE TYPE "CampaignStatus" AS ENUM ('SUSPECTED', 'ACTIVE', 'DORMANT', 'CONCLUDED');

-- CreateEnum
CREATE TYPE "AttackDomain" AS ENUM ('ENTERPRISE', 'MOBILE', 'ICS');

-- CreateEnum
CREATE TYPE "SourceType" AS ENUM ('RSS', 'TAXII', 'MISP', 'CSV', 'JSON', 'TEXT', 'MANUAL');

-- CreateEnum
CREATE TYPE "Verdict" AS ENUM ('MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "AuditAction" AS ENUM ('CREATE', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT', 'LOGIN_FAILED', 'ENRICH', 'EXPORT', 'IMPORT');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'ANALYST',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,
    "userAgent" TEXT,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiKey" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "scopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApiKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "action" "AuditAction" NOT NULL,
    "entityType" TEXT NOT NULL,
    "entityId" TEXT,
    "userId" TEXT,
    "changes" JSONB,
    "ipAddress" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ThreatActor" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT,
    "attackGroupId" TEXT,
    "country" TEXT,
    "motivation" "Motivation" NOT NULL DEFAULT 'UNKNOWN',
    "sophistication" "Sophistication",
    "firstSeen" TIMESTAMP(3),
    "lastSeen" TIMESTAMP(3),
    "active" BOOLEAN NOT NULL DEFAULT true,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "tlp" "Tlp" NOT NULL DEFAULT 'AMBER',
    "targetSectors" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "targetCountries" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ThreatActor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ActorAlias" (
    "id" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "alias" TEXT NOT NULL,
    "namedBy" TEXT,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ActorAlias_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Campaign" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT,
    "status" "CampaignStatus" NOT NULL DEFAULT 'SUSPECTED',
    "startDate" TIMESTAMP(3),
    "endDate" TIMESTAMP(3),
    "targetSectors" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "targetCountries" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "tlp" "Tlp" NOT NULL DEFAULT 'AMBER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Campaign_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Indicator" (
    "id" TEXT NOT NULL,
    "type" "IndicatorType" NOT NULL,
    "value" TEXT NOT NULL,
    "normalizedValue" TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "severity" "Severity" NOT NULL DEFAULT 'MEDIUM',
    "tlp" "Tlp" NOT NULL DEFAULT 'AMBER',
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "expiresAt" TIMESTAMP(3),
    "whitelisted" BOOLEAN NOT NULL DEFAULT false,
    "sourceId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Indicator_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Enrichment" (
    "id" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "rawResponse" JSONB NOT NULL,
    "verdict" "Verdict" NOT NULL DEFAULT 'UNKNOWN',
    "score" INTEGER,
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "error" TEXT,

    CONSTRAINT "Enrichment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Malware" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "aliases" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "family" TEXT,
    "description" TEXT,
    "attackId" TEXT,
    "platforms" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Malware_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Tool" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "aliases" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "description" TEXT,
    "attackId" TEXT,
    "dualUse" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tool_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Technique" (
    "id" TEXT NOT NULL,
    "attackId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "tactic" TEXT NOT NULL,
    "domain" "AttackDomain" NOT NULL DEFAULT 'ENTERPRISE',
    "platforms" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "dataSources" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "detection" TEXT,
    "isSubtechnique" BOOLEAN NOT NULL DEFAULT false,
    "parentId" TEXT,
    "deprecated" BOOLEAN NOT NULL DEFAULT false,
    "attackVersion" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Technique_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "summary" TEXT,
    "published" BOOLEAN NOT NULL DEFAULT false,
    "publishedAt" TIMESTAMP(3),
    "authorId" TEXT,
    "tlp" "Tlp" NOT NULL DEFAULT 'AMBER',
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "sourceUrl" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Source" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "SourceType" NOT NULL,
    "url" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "schedule" TEXT,
    "lastRunAt" TIMESTAMP(3),
    "lastStatus" TEXT,
    "lastError" TEXT,
    "itemsIngested" INTEGER NOT NULL DEFAULT 0,
    "itemsDuped" INTEGER NOT NULL DEFAULT 0,
    "errorCount" INTEGER NOT NULL DEFAULT 0,
    "defaultTlp" "Tlp" NOT NULL DEFAULT 'AMBER',
    "defaultConfidence" INTEGER NOT NULL DEFAULT 50,
    "decayHalfLifeDays" INTEGER,
    "parserConfig" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Source_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NewsItem" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "summary" TEXT,
    "url" TEXT NOT NULL,
    "publishedAt" TIMESTAMP(3) NOT NULL,
    "sourceId" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "relevanceScore" INTEGER NOT NULL DEFAULT 0,
    "linkedActorIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "linkedCveIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "NewsItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Vulnerability" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "description" TEXT,
    "cvssV3" DOUBLE PRECISION,
    "cvssV4" DOUBLE PRECISION,
    "epssScore" DOUBLE PRECISION,
    "knownExploited" BOOLEAN NOT NULL DEFAULT false,
    "kevDateAdded" TIMESTAMP(3),
    "publishedAt" TIMESTAMP(3),
    "vendorRefs" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Vulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HuntQuery" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "query" JSONB NOT NULL,
    "schedule" TEXT,
    "lastRunAt" TIMESTAMP(3),
    "lastHitCount" INTEGER NOT NULL DEFAULT 0,
    "notifyOnHit" BOOLEAN NOT NULL DEFAULT false,
    "ownerId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "HuntQuery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ActorTechnique" (
    "actorId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "notes" TEXT,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ActorTechnique_pkey" PRIMARY KEY ("actorId","techniqueId")
);

-- CreateTable
CREATE TABLE "ActorMalware" (
    "actorId" TEXT NOT NULL,
    "malwareId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ActorMalware_pkey" PRIMARY KEY ("actorId","malwareId")
);

-- CreateTable
CREATE TABLE "ActorTool" (
    "actorId" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ActorTool_pkey" PRIMARY KEY ("actorId","toolId")
);

-- CreateTable
CREATE TABLE "ActorIndicator" (
    "actorId" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ActorIndicator_pkey" PRIMARY KEY ("actorId","indicatorId")
);

-- CreateTable
CREATE TABLE "CampaignActor" (
    "campaignId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CampaignActor_pkey" PRIMARY KEY ("campaignId","actorId")
);

-- CreateTable
CREATE TABLE "CampaignTechnique" (
    "campaignId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CampaignTechnique_pkey" PRIMARY KEY ("campaignId","techniqueId")
);

-- CreateTable
CREATE TABLE "CampaignIndicator" (
    "campaignId" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CampaignIndicator_pkey" PRIMARY KEY ("campaignId","indicatorId")
);

-- CreateTable
CREATE TABLE "ReportActor" (
    "reportId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportActor_pkey" PRIMARY KEY ("reportId","actorId")
);

-- CreateTable
CREATE TABLE "ReportIndicator" (
    "reportId" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportIndicator_pkey" PRIMARY KEY ("reportId","indicatorId")
);

-- CreateTable
CREATE TABLE "ReportTechnique" (
    "reportId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "addedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportTechnique_pkey" PRIMARY KEY ("reportId","techniqueId")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Session_tokenHash_key" ON "Session"("tokenHash");

-- CreateIndex
CREATE INDEX "Session_userId_idx" ON "Session"("userId");

-- CreateIndex
CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "ApiKey_keyHash_key" ON "ApiKey"("keyHash");

-- CreateIndex
CREATE INDEX "ApiKey_userId_idx" ON "ApiKey"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_entityType_entityId_idx" ON "AuditLog"("entityType", "entityId");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ThreatActor_name_key" ON "ThreatActor"("name");

-- CreateIndex
CREATE UNIQUE INDEX "ThreatActor_slug_key" ON "ThreatActor"("slug");

-- CreateIndex
CREATE INDEX "ThreatActor_attackGroupId_idx" ON "ThreatActor"("attackGroupId");

-- CreateIndex
CREATE INDEX "ThreatActor_active_idx" ON "ThreatActor"("active");

-- CreateIndex
CREATE INDEX "ActorAlias_alias_idx" ON "ActorAlias"("alias");

-- CreateIndex
CREATE UNIQUE INDEX "ActorAlias_actorId_alias_key" ON "ActorAlias"("actorId", "alias");

-- CreateIndex
CREATE UNIQUE INDEX "Campaign_name_key" ON "Campaign"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Campaign_slug_key" ON "Campaign"("slug");

-- CreateIndex
CREATE INDEX "Campaign_status_idx" ON "Campaign"("status");

-- CreateIndex
CREATE INDEX "Indicator_type_idx" ON "Indicator"("type");

-- CreateIndex
CREATE INDEX "Indicator_lastSeen_idx" ON "Indicator"("lastSeen");

-- CreateIndex
CREATE INDEX "Indicator_severity_idx" ON "Indicator"("severity");

-- CreateIndex
CREATE INDEX "Indicator_whitelisted_idx" ON "Indicator"("whitelisted");

-- CreateIndex
CREATE INDEX "Indicator_sourceId_idx" ON "Indicator"("sourceId");

-- CreateIndex
CREATE UNIQUE INDEX "Indicator_type_normalizedValue_key" ON "Indicator"("type", "normalizedValue");

-- CreateIndex
CREATE INDEX "Enrichment_provider_idx" ON "Enrichment"("provider");

-- CreateIndex
CREATE INDEX "Enrichment_expiresAt_idx" ON "Enrichment"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "Enrichment_indicatorId_provider_key" ON "Enrichment"("indicatorId", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "Malware_name_key" ON "Malware"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Malware_attackId_key" ON "Malware"("attackId");

-- CreateIndex
CREATE UNIQUE INDEX "Tool_name_key" ON "Tool"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Tool_attackId_key" ON "Tool"("attackId");

-- CreateIndex
CREATE INDEX "Technique_tactic_idx" ON "Technique"("tactic");

-- CreateIndex
CREATE INDEX "Technique_domain_idx" ON "Technique"("domain");

-- CreateIndex
CREATE INDEX "Technique_deprecated_idx" ON "Technique"("deprecated");

-- CreateIndex
CREATE UNIQUE INDEX "Technique_attackId_domain_key" ON "Technique"("attackId", "domain");

-- CreateIndex
CREATE UNIQUE INDEX "Report_slug_key" ON "Report"("slug");

-- CreateIndex
CREATE INDEX "Report_published_publishedAt_idx" ON "Report"("published", "publishedAt");

-- CreateIndex
CREATE UNIQUE INDEX "Source_name_key" ON "Source"("name");

-- CreateIndex
CREATE INDEX "Source_enabled_idx" ON "Source"("enabled");

-- CreateIndex
CREATE UNIQUE INDEX "NewsItem_url_key" ON "NewsItem"("url");

-- CreateIndex
CREATE INDEX "NewsItem_publishedAt_idx" ON "NewsItem"("publishedAt");

-- CreateIndex
CREATE INDEX "NewsItem_relevanceScore_idx" ON "NewsItem"("relevanceScore");

-- CreateIndex
CREATE UNIQUE INDEX "Vulnerability_cveId_key" ON "Vulnerability"("cveId");

-- CreateIndex
CREATE INDEX "Vulnerability_knownExploited_idx" ON "Vulnerability"("knownExploited");

-- CreateIndex
CREATE INDEX "Vulnerability_epssScore_idx" ON "Vulnerability"("epssScore");

-- CreateIndex
CREATE INDEX "Vulnerability_publishedAt_idx" ON "Vulnerability"("publishedAt");

-- CreateIndex
CREATE INDEX "HuntQuery_ownerId_idx" ON "HuntQuery"("ownerId");

-- CreateIndex
CREATE INDEX "ActorTechnique_techniqueId_idx" ON "ActorTechnique"("techniqueId");

-- CreateIndex
CREATE INDEX "ActorMalware_malwareId_idx" ON "ActorMalware"("malwareId");

-- CreateIndex
CREATE INDEX "ActorTool_toolId_idx" ON "ActorTool"("toolId");

-- CreateIndex
CREATE INDEX "ActorIndicator_indicatorId_idx" ON "ActorIndicator"("indicatorId");

-- CreateIndex
CREATE INDEX "CampaignActor_actorId_idx" ON "CampaignActor"("actorId");

-- CreateIndex
CREATE INDEX "CampaignTechnique_techniqueId_idx" ON "CampaignTechnique"("techniqueId");

-- CreateIndex
CREATE INDEX "CampaignIndicator_indicatorId_idx" ON "CampaignIndicator"("indicatorId");

-- CreateIndex
CREATE INDEX "ReportActor_actorId_idx" ON "ReportActor"("actorId");

-- CreateIndex
CREATE INDEX "ReportIndicator_indicatorId_idx" ON "ReportIndicator"("indicatorId");

-- CreateIndex
CREATE INDEX "ReportTechnique_techniqueId_idx" ON "ReportTechnique"("techniqueId");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiKey" ADD CONSTRAINT "ApiKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorAlias" ADD CONSTRAINT "ActorAlias_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorAlias" ADD CONSTRAINT "ActorAlias_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Indicator" ADD CONSTRAINT "Indicator_sourceId_fkey" FOREIGN KEY ("sourceId") REFERENCES "Source"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Enrichment" ADD CONSTRAINT "Enrichment_indicatorId_fkey" FOREIGN KEY ("indicatorId") REFERENCES "Indicator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Technique" ADD CONSTRAINT "Technique_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "Technique"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NewsItem" ADD CONSTRAINT "NewsItem_sourceId_fkey" FOREIGN KEY ("sourceId") REFERENCES "Source"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HuntQuery" ADD CONSTRAINT "HuntQuery_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorTechnique" ADD CONSTRAINT "ActorTechnique_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorTechnique" ADD CONSTRAINT "ActorTechnique_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorTechnique" ADD CONSTRAINT "ActorTechnique_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorMalware" ADD CONSTRAINT "ActorMalware_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorMalware" ADD CONSTRAINT "ActorMalware_malwareId_fkey" FOREIGN KEY ("malwareId") REFERENCES "Malware"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorMalware" ADD CONSTRAINT "ActorMalware_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorTool" ADD CONSTRAINT "ActorTool_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorTool" ADD CONSTRAINT "ActorTool_toolId_fkey" FOREIGN KEY ("toolId") REFERENCES "Tool"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorTool" ADD CONSTRAINT "ActorTool_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorIndicator" ADD CONSTRAINT "ActorIndicator_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorIndicator" ADD CONSTRAINT "ActorIndicator_indicatorId_fkey" FOREIGN KEY ("indicatorId") REFERENCES "Indicator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorIndicator" ADD CONSTRAINT "ActorIndicator_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignActor" ADD CONSTRAINT "CampaignActor_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "Campaign"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignActor" ADD CONSTRAINT "CampaignActor_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignActor" ADD CONSTRAINT "CampaignActor_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignTechnique" ADD CONSTRAINT "CampaignTechnique_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "Campaign"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignTechnique" ADD CONSTRAINT "CampaignTechnique_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignTechnique" ADD CONSTRAINT "CampaignTechnique_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignIndicator" ADD CONSTRAINT "CampaignIndicator_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "Campaign"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignIndicator" ADD CONSTRAINT "CampaignIndicator_indicatorId_fkey" FOREIGN KEY ("indicatorId") REFERENCES "Indicator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignIndicator" ADD CONSTRAINT "CampaignIndicator_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportActor" ADD CONSTRAINT "ReportActor_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "Report"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportActor" ADD CONSTRAINT "ReportActor_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportActor" ADD CONSTRAINT "ReportActor_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportIndicator" ADD CONSTRAINT "ReportIndicator_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "Report"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportIndicator" ADD CONSTRAINT "ReportIndicator_indicatorId_fkey" FOREIGN KEY ("indicatorId") REFERENCES "Indicator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportIndicator" ADD CONSTRAINT "ReportIndicator_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportTechnique" ADD CONSTRAINT "ReportTechnique_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "Report"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportTechnique" ADD CONSTRAINT "ReportTechnique_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportTechnique" ADD CONSTRAINT "ReportTechnique_addedById_fkey" FOREIGN KEY ("addedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
