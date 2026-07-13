-- 0020_conversation_source_metadata: whitelisted, content-free source metadata
-- for filtering imported sessions. Raw messages, tool arguments/results,
-- patches, errors, and attachment content MUST NOT enter this table.

ALTER TABLE conversation_ingestion_runs ADD COLUMN source_export_id TEXT;

CREATE TABLE conversation_source_metadata (
    conversation_id      TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    source_product       TEXT NOT NULL
        CHECK (source_product IN ('claude_code', 'claude', 'chatgpt')),
    session_id           TEXT NOT NULL,
    project              TEXT,
    repository           TEXT,
    working_directory    TEXT,
    git_branch           TEXT,
    git_commit           TEXT,
    source_file_identity TEXT,
    models_json          TEXT NOT NULL DEFAULT '[]',
    source_created_at    TEXT,
    source_updated_at    TEXT
);

CREATE INDEX idx_conversation_source_metadata_session
    ON conversation_source_metadata(source_product, session_id);
CREATE INDEX idx_conversation_source_metadata_project
    ON conversation_source_metadata(source_product, project, source_updated_at);
CREATE INDEX idx_conversation_source_metadata_repository
    ON conversation_source_metadata(source_product, repository, source_updated_at);
CREATE INDEX idx_conversation_source_metadata_branch
    ON conversation_source_metadata(source_product, git_branch, source_updated_at);
