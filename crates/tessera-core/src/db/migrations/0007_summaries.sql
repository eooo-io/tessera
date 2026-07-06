-- 0007_summaries: one stored summary per (version, summarizer). The summary
-- text lives in an encrypted blob (blob_hash); this row records which
-- summarizer produced it and where it ran (local vs a per-item cloud opt-in).
-- Regeneration replaces the blob_hash in place; provenance keeps the history.

CREATE TABLE summaries (
    id                  TEXT PRIMARY KEY,
    artifact_version_id TEXT NOT NULL REFERENCES artifact_versions(id),
    blob_hash           TEXT NOT NULL,
    summarizer          TEXT NOT NULL,
    summarizer_version  TEXT NOT NULL,
    locality            TEXT NOT NULL DEFAULT 'local'
        CHECK (locality IN ('local', 'cloud')),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    UNIQUE (artifact_version_id, summarizer, summarizer_version)
);

CREATE INDEX idx_summaries_version ON summaries(artifact_version_id);
