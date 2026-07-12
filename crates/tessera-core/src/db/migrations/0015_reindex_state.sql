-- 0015_reindex_state: one durable shadow index. The active index is never
-- modified until the shadow is complete and activation commits atomically.

CREATE VIRTUAL TABLE reindex_chunk_embeddings USING vec0(embedding float[384]);

CREATE TABLE reindex_embeddings_map (
    chunk_id      TEXT PRIMARY KEY REFERENCES chunks(id),
    vec_rowid     INTEGER NOT NULL UNIQUE,
    model_version TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE reindex_state (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    model_version TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('running', 'cancel_requested', 'complete')),
    total_chunks  INTEGER NOT NULL,
    started_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
