-- 0013_pairing_grant_version: bind every pairing to the exact lens revision
-- approved by the owner and make grant fields immutable after approval.

ALTER TABLE pairings ADD COLUMN lens_updated_at TEXT;

-- Existing pre-release pairings are bound to the lens revision present when
-- this migration is applied. Missing/deleted lenses remain NULL and fail
-- closed when the guardian resolves the pairing.
UPDATE pairings
SET lens_updated_at = (
    SELECT lenses.updated_at FROM lenses WHERE lenses.id = pairings.lens_id
);

CREATE TRIGGER pairings_immutable_grant
BEFORE UPDATE OF lens_id, purpose, agent_name, ttl_minutes, approved_at,
                 oauth_client_id, lens_updated_at ON pairings
BEGIN
    SELECT RAISE(ABORT, 'pairing grants are immutable; create a new pairing');
END;
