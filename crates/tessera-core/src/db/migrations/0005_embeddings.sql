-- 0005_embeddings: vector storage. chunk_embeddings is a sqlite-vec vec0
-- virtual table (the extension is registered by open_database before
-- migrations run); embeddings_map ties chunks to vec rowids and records the
-- producing model version so mixed-model queries can be refused.

CREATE VIRTUAL TABLE chunk_embeddings USING vec0(embedding float[384]);

CREATE TABLE embeddings_map (
    chunk_id      TEXT PRIMARY KEY REFERENCES chunks(id),
    vec_rowid     INTEGER NOT NULL UNIQUE,
    model_version TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE INDEX idx_embeddings_model ON embeddings_map(model_version);
