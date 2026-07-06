-- 0009_sessions: live guardian sessions. A row is written when a guardian
-- binds a connection and updated when it closes, expires, or is revoked. The
-- guardian re-reads status on every tool call, so a revocation (written by the
-- CLI to this same WAL database) takes effect on the next call. Expiry is
-- computed from expires_at, not stored, so it needs no writer.

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    pairing_id  TEXT NOT NULL,
    lens_id     TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    agent_name  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    ended_at    TEXT,
    status      TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'closed', 'revoked')),
    receipt_id  TEXT
);

CREATE INDEX idx_sessions_status ON sessions(status);
