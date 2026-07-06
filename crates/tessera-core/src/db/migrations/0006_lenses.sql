-- 0006_lenses: reusable access policies. The full policy is stored as JSON
-- (validated against spec/lens-policy.schema.json before every write); id and
-- name are denormalized into columns for cheap listing and lookup.

CREATE TABLE lenses (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX idx_lenses_name ON lenses(name);
