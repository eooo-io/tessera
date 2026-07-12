-- 0012_http_oauth: preregistered public clients, one-time PKCE codes, and
-- opaque access-token bindings for the MCP Streamable HTTP transport.

ALTER TABLE pairings ADD COLUMN oauth_client_id TEXT;
CREATE UNIQUE INDEX idx_pairings_oauth_client ON pairings(oauth_client_id, lens_id)
WHERE oauth_client_id IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE oauth_clients (
    client_id          TEXT PRIMARY KEY,
    client_name        TEXT NOT NULL,
    redirect_uris_json TEXT NOT NULL,
    created_at         TEXT NOT NULL
);

CREATE TABLE oauth_authorization_codes (
    code_hash     TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL REFERENCES oauth_clients(client_id),
    pairing_id    TEXT NOT NULL REFERENCES pairings(id),
    redirect_uri  TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    resource      TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    used_at       TEXT
);

CREATE TABLE oauth_access_tokens (
    token_hash  TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL REFERENCES oauth_clients(client_id),
    pairing_id  TEXT NOT NULL REFERENCES pairings(id),
    lens_id     TEXT NOT NULL,
    resource    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE INDEX idx_oauth_tokens_pairing ON oauth_access_tokens(pairing_id);
