-- 0011_processing_errors: actionable, durable per-artifact processing errors
-- for owner quarantine review. Content stays encrypted; this stores bounded
-- stage/error metadata only.

CREATE TABLE processing_errors (
    id          TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    stage       TEXT NOT NULL,
    message     TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX idx_processing_errors_active
    ON processing_errors(artifact_id, stage, resolved_at);
