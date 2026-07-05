-- 0002_derived_text: extraction outputs. One row per (version, extractor,
-- extractor_version) so re-extraction is skippable and upgrades re-run.

CREATE TABLE derived_text (
    id                  TEXT PRIMARY KEY,
    artifact_version_id TEXT NOT NULL REFERENCES artifact_versions(id),
    blob_hash           TEXT NOT NULL,
    extractor           TEXT NOT NULL,
    extractor_version   TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    UNIQUE (artifact_version_id, extractor, extractor_version)
);

CREATE INDEX idx_derived_text_version ON derived_text(artifact_version_id);
