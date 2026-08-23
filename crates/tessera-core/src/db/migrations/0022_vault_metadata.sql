-- 0022_vault_metadata: private manifest values protected with the database.

CREATE TABLE vault_metadata (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
