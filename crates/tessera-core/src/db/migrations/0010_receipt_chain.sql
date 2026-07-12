-- 0010_receipt_chain: durable, concurrency-safe receipt-chain head and index.
-- Receipt JSON remains the portable audit record. SQLite serializes the brief
-- finalization commit and records enough state to recover a committed prepared
-- file if the process stops before its final atomic rename.

CREATE TABLE receipt_chain_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_seq   INTEGER NOT NULL CHECK (next_seq >= 0),
    head_hash  TEXT,
    updated_at TEXT NOT NULL
);

INSERT INTO receipt_chain_state (singleton, next_seq, head_hash, updated_at)
VALUES (1, 0, NULL, datetime('now'));

CREATE TABLE receipts_index (
    receipt_id       TEXT PRIMARY KEY,
    seq              INTEGER NOT NULL UNIQUE CHECK (seq >= 0),
    prev_receipt_hash TEXT,
    self_hash        TEXT NOT NULL,
    file_name        TEXT NOT NULL UNIQUE,
    committed_at     TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_receipts_index_seq ON receipts_index(seq);
