-- 0019_conversation_ingestion_runs: source-neutral, resumable ingestion run
-- ledger. Error fields are bounded structural summaries and must never contain
-- source content.

CREATE TABLE conversation_ingestion_runs (
    id                         TEXT PRIMARY KEY,
    source_artifact_version_id TEXT NOT NULL REFERENCES artifact_versions(id),
    target_space_id            TEXT NOT NULL REFERENCES spaces(id),
    source_product             TEXT NOT NULL
        CHECK (source_product IN ('claude_code', 'claude', 'chatgpt')),
    source_hash                TEXT NOT NULL,
    parser_name                TEXT NOT NULL,
    parser_version             TEXT NOT NULL,
    normalizer_name            TEXT NOT NULL,
    normalizer_version         TEXT NOT NULL,
    status                     TEXT NOT NULL
        CHECK (status IN ('running', 'interrupted', 'completed', 'failed')),
    discovered_count           INTEGER NOT NULL DEFAULT 0 CHECK (discovered_count >= 0),
    imported_count             INTEGER NOT NULL DEFAULT 0 CHECK (imported_count >= 0),
    unchanged_count            INTEGER NOT NULL DEFAULT 0 CHECK (unchanged_count >= 0),
    updated_count              INTEGER NOT NULL DEFAULT 0 CHECK (updated_count >= 0),
    quarantined_count          INTEGER NOT NULL DEFAULT 0 CHECK (quarantined_count >= 0),
    failed_count               INTEGER NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    checkpoint_ordinal         INTEGER NOT NULL DEFAULT 0 CHECK (checkpoint_ordinal >= 0),
    retry_count                INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    error_code                 TEXT,
    safe_error_summary         TEXT,
    started_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL,
    completed_at               TEXT
);

CREATE INDEX idx_conversation_ingestion_runs_source
    ON conversation_ingestion_runs(source_product, source_hash, started_at);
CREATE INDEX idx_conversation_ingestion_runs_status
    ON conversation_ingestion_runs(status, updated_at);

CREATE TABLE conversation_ingestion_items (
    id                                TEXT PRIMARY KEY,
    run_id                            TEXT NOT NULL REFERENCES conversation_ingestion_runs(id) ON DELETE CASCADE,
    ordinal                           INTEGER NOT NULL CHECK (ordinal >= 0),
    source_conversation_id            TEXT NOT NULL,
    source_digest                     TEXT,
    status                            TEXT NOT NULL
        CHECK (status IN ('pending', 'imported', 'unchanged', 'updated', 'quarantined', 'failed')),
    persisted_conversation_id         TEXT REFERENCES conversations(id),
    previous_persisted_conversation_id TEXT REFERENCES conversations(id),
    derived_text_id                   TEXT,
    derivation_hash                   TEXT,
    embedding_model_version           TEXT,
    error_code                        TEXT,
    safe_error_summary                TEXT,
    retry_count                       INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    attempted_at                      TEXT,
    completed_at                      TEXT,
    UNIQUE (run_id, ordinal)
);

CREATE INDEX idx_conversation_ingestion_items_run_status
    ON conversation_ingestion_items(run_id, status, ordinal);
CREATE INDEX idx_conversation_ingestion_items_source
    ON conversation_ingestion_items(source_conversation_id);

-- Current logical conversation identity across full/superset/corrected archive
-- snapshots. Source product is part of the key so unrelated products may reuse
-- the same source-native id.
CREATE TABLE conversation_ingestion_heads (
    source_product              TEXT NOT NULL,
    source_conversation_id      TEXT NOT NULL,
    persisted_conversation_id   TEXT NOT NULL REFERENCES conversations(id),
    source_digest               TEXT NOT NULL,
    parser_name                 TEXT NOT NULL,
    parser_version              TEXT NOT NULL,
    normalizer_name             TEXT NOT NULL,
    normalizer_version          TEXT NOT NULL,
    run_id                      TEXT NOT NULL REFERENCES conversation_ingestion_runs(id),
    item_id                     TEXT NOT NULL REFERENCES conversation_ingestion_items(id),
    updated_at                  TEXT NOT NULL,
    PRIMARY KEY (source_product, source_conversation_id)
);

CREATE TABLE conversation_ingestion_replacements (
    id                                TEXT PRIMARY KEY,
    prior_persisted_conversation_id   TEXT NOT NULL REFERENCES conversations(id),
    replacement_conversation_id       TEXT NOT NULL REFERENCES conversations(id),
    run_id                            TEXT NOT NULL REFERENCES conversation_ingestion_runs(id),
    item_id                           TEXT NOT NULL REFERENCES conversation_ingestion_items(id),
    relationship                      TEXT NOT NULL
        CHECK (relationship IN ('corrected_source', 'parser_upgrade', 'normalizer_upgrade')),
    created_at                        TEXT NOT NULL,
    UNIQUE (prior_persisted_conversation_id, replacement_conversation_id)
);

CREATE INDEX idx_conversation_ingestion_replacements_new
    ON conversation_ingestion_replacements(replacement_conversation_id);
