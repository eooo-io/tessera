-- 0018_conversation_provenance: exact branch/message/content-part lineage for
-- source-neutral conversation archives. Content-bearing values remain in
-- encrypted blobs; these tables contain policy and citation metadata only.

CREATE TABLE conversation_archives (
    id                         TEXT PRIMARY KEY,
    source_artifact_version_id TEXT NOT NULL REFERENCES artifact_versions(id),
    schema_version             TEXT NOT NULL,
    source_product             TEXT NOT NULL
        CHECK (source_product IN ('claude_code', 'claude', 'chatgpt')),
    source_hash                TEXT NOT NULL,
    normal_form_blob_hash      TEXT NOT NULL,
    parser_name                TEXT NOT NULL,
    parser_version             TEXT NOT NULL,
    normalizer_name            TEXT NOT NULL,
    normalizer_version         TEXT NOT NULL,
    locality                   TEXT NOT NULL CHECK (locality IN ('local', 'cloud')),
    processed_at               TEXT NOT NULL,
    UNIQUE (source_hash, parser_name, parser_version, normalizer_name, normalizer_version)
);

CREATE INDEX idx_conversation_archives_source_version
    ON conversation_archives(source_artifact_version_id);

-- Each conversation owns an ordinary artifact. Its sensitivity and
-- quarantine state therefore flow through the existing lens boundary.
CREATE TABLE conversations (
    id                            TEXT PRIMARY KEY,
    archive_id                    TEXT NOT NULL REFERENCES conversation_archives(id) ON DELETE CASCADE,
    artifact_version_id           TEXT NOT NULL UNIQUE REFERENCES artifact_versions(id) ON DELETE CASCADE,
    source_conversation_id        TEXT NOT NULL,
    source_created_at             TEXT,
    source_updated_at             TEXT,
    selected_branch_endpoint_id   TEXT NOT NULL,
    canonical_hash                TEXT NOT NULL,
    created_at                    TEXT NOT NULL,
    UNIQUE (archive_id, source_conversation_id)
);

CREATE INDEX idx_conversations_archive ON conversations(archive_id);
CREATE INDEX idx_conversations_source_dates
    ON conversations(source_created_at, source_updated_at);

CREATE TABLE conversation_source_records (
    id                TEXT PRIMARY KEY,
    conversation_id   TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    source_record_id  TEXT NOT NULL,
    record_index      INTEGER NOT NULL CHECK (record_index >= 0),
    source_id         TEXT,
    byte_start        INTEGER CHECK (byte_start >= 0),
    byte_end          INTEGER CHECK (byte_end >= 0),
    line_start        INTEGER CHECK (line_start >= 1),
    line_end          INTEGER CHECK (line_end >= 1),
    CHECK (byte_start IS NULL OR byte_end IS NULL OR byte_end >= byte_start),
    CHECK (line_start IS NULL OR line_end IS NULL OR line_end >= line_start),
    UNIQUE (conversation_id, source_record_id),
    UNIQUE (conversation_id, record_index)
);

CREATE TABLE conversation_nodes (
    id                 TEXT PRIMARY KEY,
    conversation_id    TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    source_node_id     TEXT NOT NULL,
    parent_id          TEXT REFERENCES conversation_nodes(id) DEFERRABLE INITIALLY DEFERRED,
    role               TEXT NOT NULL
        CHECK (role IN ('user', 'assistant', 'system', 'tool', 'unknown')),
    source_state       TEXT NOT NULL
        CHECK (source_state IN ('visible', 'hidden', 'deleted', 'partial', 'compacted', 'malformed', 'unsupported')),
    source_timestamp   TEXT,
    selected_order     INTEGER CHECK (selected_order >= 0),
    UNIQUE (conversation_id, source_node_id),
    UNIQUE (conversation_id, selected_order)
);

CREATE INDEX idx_conversation_nodes_parent ON conversation_nodes(parent_id);
CREATE INDEX idx_conversation_nodes_state ON conversation_nodes(source_state);

CREATE TABLE conversation_node_source_records (
    node_id          TEXT NOT NULL REFERENCES conversation_nodes(id) ON DELETE CASCADE,
    source_record_id TEXT NOT NULL REFERENCES conversation_source_records(id) ON DELETE CASCADE,
    PRIMARY KEY (node_id, source_record_id)
);

CREATE TABLE conversation_content_parts (
    id                    TEXT PRIMARY KEY,
    node_id               TEXT NOT NULL REFERENCES conversation_nodes(id) ON DELETE CASCADE,
    source_part_id        TEXT NOT NULL,
    part_index            INTEGER NOT NULL CHECK (part_index >= 0),
    kind                  TEXT NOT NULL
        CHECK (kind IN ('text', 'code', 'tool_use', 'tool_result', 'attachment', 'file', 'image', 'compaction', 'error', 'unsupported')),
    tool_use_part_id      TEXT REFERENCES conversation_content_parts(id) DEFERRABLE INITIALLY DEFERRED,
    attachment_id         TEXT,
    attachment_state      TEXT
        CHECK (attachment_state IN ('preserved', 'missing', 'external_unfetched', 'unsupported')),
    attachment_hash       TEXT,
    UNIQUE (node_id, part_index),
    UNIQUE (node_id, source_part_id)
);

CREATE INDEX idx_conversation_parts_tool_use
    ON conversation_content_parts(tool_use_part_id);

CREATE TABLE conversation_derivations (
    id                    TEXT PRIMARY KEY,
    conversation_id       TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    derived_text_id       TEXT NOT NULL UNIQUE REFERENCES derived_text(id) ON DELETE CASCADE,
    normalized_blob_hash  TEXT NOT NULL,
    derivation_hash       TEXT NOT NULL UNIQUE,
    renderer_name         TEXT NOT NULL,
    renderer_version      TEXT NOT NULL,
    chunker_name          TEXT NOT NULL,
    chunker_version       TEXT NOT NULL,
    target_tokens         INTEGER NOT NULL CHECK (target_tokens > 0),
    overlap_tokens        INTEGER NOT NULL CHECK (overlap_tokens >= 0),
    locality              TEXT NOT NULL CHECK (locality IN ('local', 'cloud')),
    processed_at          TEXT NOT NULL,
    UNIQUE (conversation_id, renderer_name, renderer_version, chunker_name,
            chunker_version, target_tokens, overlap_tokens)
);

CREATE INDEX idx_conversation_derivations_conversation
    ON conversation_derivations(conversation_id);

-- Node spans cover the whole rendered event, while optional part spans cover
-- exact content-part events inside it. All ranges index the encrypted
-- normalized transcript blob.
CREATE TABLE conversation_spans (
    id                TEXT PRIMARY KEY,
    derivation_id     TEXT NOT NULL REFERENCES conversation_derivations(id) ON DELETE CASCADE,
    node_id           TEXT NOT NULL REFERENCES conversation_nodes(id) ON DELETE CASCADE,
    part_id           TEXT REFERENCES conversation_content_parts(id) ON DELETE CASCADE,
    byte_offset_start INTEGER NOT NULL CHECK (byte_offset_start >= 0),
    byte_offset_end   INTEGER NOT NULL CHECK (byte_offset_end > byte_offset_start),
    UNIQUE (derivation_id, node_id, part_id)
);

CREATE INDEX idx_conversation_spans_range
    ON conversation_spans(derivation_id, byte_offset_start, byte_offset_end);

CREATE TABLE conversation_chunk_map (
    chunk_id                TEXT PRIMARY KEY REFERENCES chunks(id) ON DELETE CASCADE,
    derivation_id           TEXT NOT NULL REFERENCES conversation_derivations(id) ON DELETE CASCADE,
    first_node_id           TEXT NOT NULL REFERENCES conversation_nodes(id),
    last_node_id            TEXT NOT NULL REFERENCES conversation_nodes(id),
    branch_endpoint_node_id TEXT NOT NULL REFERENCES conversation_nodes(id),
    mapped_at               TEXT NOT NULL
);

CREATE INDEX idx_conversation_chunk_map_derivation
    ON conversation_chunk_map(derivation_id);
