-- 0004_state_transitions: audit trail for quarantine state changes. A row
-- is written in the same transaction as the change itself.

CREATE TABLE state_transitions (
    id          TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    from_state  TEXT NOT NULL,
    to_state    TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT 'owner',
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_transitions_artifact ON state_transitions(artifact_id);
