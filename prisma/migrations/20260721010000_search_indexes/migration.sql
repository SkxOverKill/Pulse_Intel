-- Search indexes for Phase 2.
--
-- These are *expression* indexes rather than generated tsvector columns. A
-- generated column would not exist in schema.prisma, so every future
-- `migrate diff` would try to drop it. Expression indexes keep the Prisma
-- model as the single source of truth for columns while still giving Postgres
-- what it needs.
--
-- Any query wanting these indexes must use the identical expression — see
-- src/lib/search/query.ts, which builds them from the same shape.

-- --- Trigram indexes: fuzzy / substring matching -------------------------
-- Actor naming is the hard part of APT tracking ("APT29" vs "Cozy Bear" vs a
-- typo), so both the canonical name and every alias are trigram-indexed.
CREATE INDEX IF NOT EXISTS "ThreatActor_name_trgm_idx"
  ON "ThreatActor" USING GIN ("name" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "ActorAlias_alias_trgm_idx"
  ON "ActorAlias" USING GIN ("alias" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "Campaign_name_trgm_idx"
  ON "Campaign" USING GIN ("name" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "Malware_name_trgm_idx"
  ON "Malware" USING GIN ("name" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "Tool_name_trgm_idx"
  ON "Tool" USING GIN ("name" gin_trgm_ops);

-- Substring search over IOCs: "show me everything under evil.com".
CREATE INDEX IF NOT EXISTS "Indicator_normalized_trgm_idx"
  ON "Indicator" USING GIN ("normalizedValue" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "Vulnerability_cve_trgm_idx"
  ON "Vulnerability" USING GIN ("cveId" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "Technique_name_trgm_idx"
  ON "Technique" USING GIN ("name" gin_trgm_ops);

-- --- Full-text indexes ---------------------------------------------------
-- Weighting: A = title/name, B = summary, C = body. Postgres ranks A matches
-- above C, so an actor named in a title outranks one mentioned in passing.
CREATE INDEX IF NOT EXISTS "Report_fts_idx" ON "Report" USING GIN (
  (
    setweight(to_tsvector('english', coalesce("title", '')), 'A') ||
    setweight(to_tsvector('english', coalesce("summary", '')), 'B') ||
    setweight(to_tsvector('english', coalesce("body", '')), 'C')
  )
);

CREATE INDEX IF NOT EXISTS "ThreatActor_fts_idx" ON "ThreatActor" USING GIN (
  (
    setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
    setweight(to_tsvector('english', coalesce("description", '')), 'B')
  )
);

CREATE INDEX IF NOT EXISTS "Campaign_fts_idx" ON "Campaign" USING GIN (
  (
    setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
    setweight(to_tsvector('english', coalesce("description", '')), 'B')
  )
);

CREATE INDEX IF NOT EXISTS "NewsItem_fts_idx" ON "NewsItem" USING GIN (
  (
    setweight(to_tsvector('english', coalesce("title", '')), 'A') ||
    setweight(to_tsvector('english', coalesce("summary", '')), 'B')
  )
);

CREATE INDEX IF NOT EXISTS "Technique_fts_idx" ON "Technique" USING GIN (
  (
    setweight(to_tsvector('english', coalesce("name", '')), 'A') ||
    setweight(to_tsvector('english', coalesce("description", '')), 'B')
  )
);
