-- 0008_pairings: owner-approved agent pairings. A pairing authorizes a
-- guardian connection to bind to a specific lens for a stated purpose; the
-- guardian refuses to serve any pairing that is absent or revoked. lens_id is
-- a soft reference (the guardian re-checks the lens still exists at bind time).

CREATE TABLE pairings (
    id           TEXT PRIMARY KEY,
    lens_id      TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    agent_name   TEXT NOT NULL,
    ttl_minutes  INTEGER NOT NULL,
    approved_at  TEXT NOT NULL,
    revoked_at   TEXT
);

CREATE INDEX idx_pairings_lens ON pairings(lens_id);
