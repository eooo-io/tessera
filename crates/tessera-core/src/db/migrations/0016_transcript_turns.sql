-- 0016_transcript_turns: turn and source-time coordinates for transcripts.
-- Source content remains in encrypted blobs; this table is plaintext metadata.

CREATE TABLE transcript_turns (
    id                 TEXT PRIMARY KEY,
    derived_text_id    TEXT NOT NULL REFERENCES derived_text(id) ON DELETE CASCADE,
    turn_index         INTEGER NOT NULL,
    byte_offset_start  INTEGER NOT NULL CHECK (byte_offset_start >= 0),
    byte_offset_end    INTEGER NOT NULL CHECK (byte_offset_end > byte_offset_start),
    timestamp_start_ms INTEGER,
    timestamp_end_ms   INTEGER,
    CHECK (
        (timestamp_start_ms IS NULL AND timestamp_end_ms IS NULL)
        OR (timestamp_start_ms >= 0 AND timestamp_end_ms >= timestamp_start_ms)
    ),
    UNIQUE (derived_text_id, turn_index)
);

CREATE INDEX idx_transcript_turns_derived_range
    ON transcript_turns (derived_text_id, byte_offset_start, byte_offset_end);
