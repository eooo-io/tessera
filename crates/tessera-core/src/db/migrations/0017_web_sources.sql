-- 0017_web_sources: explicit web-clip staging and source provenance.

CREATE TABLE web_staging (
    staged_filename TEXT PRIMARY KEY,
    source_url      TEXT NOT NULL,
    final_url       TEXT NOT NULL,
    title           TEXT NOT NULL,
    published_at    TEXT,
    fetched_at      TEXT NOT NULL
);

CREATE TABLE web_sources (
    artifact_version_id TEXT PRIMARY KEY REFERENCES artifact_versions(id) ON DELETE CASCADE,
    source_url          TEXT NOT NULL,
    final_url           TEXT NOT NULL,
    title               TEXT NOT NULL,
    published_at        TEXT,
    fetched_at          TEXT NOT NULL
);
