-- 0001_initial: spaces, artifacts (with quarantine state), versions, tags,
-- provenance. See spec/vault-format.md §3 and the 2026-07-04 design doc.

CREATE TABLE spaces (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    parent_id  TEXT REFERENCES spaces(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE artifacts (
    id          TEXT PRIMARY KEY,
    space_id    TEXT NOT NULL REFERENCES spaces(id),
    filename    TEXT NOT NULL,
    media_type  TEXT NOT NULL,
    sensitivity TEXT NOT NULL DEFAULT 'internal'
        CHECK (sensitivity IN ('public', 'internal', 'confidential', 'restricted')),
    -- Quarantine invariant: retrieval and lenses only ever match 'live'.
    state       TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'live', 'archived')),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX idx_artifacts_space ON artifacts(space_id);
CREATE INDEX idx_artifacts_state ON artifacts(state);

CREATE TABLE artifact_versions (
    id          TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    version     INTEGER NOT NULL,
    blob_hash   TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (artifact_id, version)
);

CREATE INDEX idx_versions_artifact ON artifact_versions(artifact_id);

CREATE TABLE tags (
    id   TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE artifact_tags (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    tag_id      TEXT NOT NULL REFERENCES tags(id),
    PRIMARY KEY (artifact_id, tag_id)
);

-- Every derived blob records where it came from and what produced it.
CREATE TABLE provenance (
    id                         TEXT PRIMARY KEY,
    derived_blob_hash          TEXT NOT NULL,
    source_artifact_version_id TEXT REFERENCES artifact_versions(id),
    tool                       TEXT NOT NULL,
    tool_version               TEXT,
    locality                   TEXT NOT NULL DEFAULT 'local'
        CHECK (locality IN ('local', 'cloud')),
    created_at                 TEXT NOT NULL
);

CREATE INDEX idx_provenance_blob ON provenance(derived_blob_hash);
