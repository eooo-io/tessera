-- 0003_chunks: retrieval units. Offsets index into the derived text blob
-- (byte positions, always on UTF-8 char boundaries) for citation precision.

CREATE TABLE chunks (
    id                TEXT PRIMARY KEY,
    derived_text_id   TEXT NOT NULL REFERENCES derived_text(id),
    chunk_index       INTEGER NOT NULL,
    byte_offset_start INTEGER NOT NULL,
    byte_offset_end   INTEGER NOT NULL,
    token_count       INTEGER NOT NULL,
    content_hash      TEXT NOT NULL,
    section_heading   TEXT,
    created_at        TEXT NOT NULL,
    UNIQUE (derived_text_id, chunk_index)
);

CREATE INDEX idx_chunks_derived ON chunks(derived_text_id);
