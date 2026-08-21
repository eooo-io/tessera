-- 0021_image_understanding: encrypted image thumbnails and searchable OCR/VLM
-- derivations with exact local/cloud and model provenance.

CREATE TABLE image_derivations (
    id                         TEXT PRIMARY KEY,
    artifact_version_id        TEXT NOT NULL REFERENCES artifact_versions(id),
    searchable_derived_text_id TEXT NOT NULL REFERENCES derived_text(id),
    thumbnail_blob_hash        TEXT NOT NULL,
    thumbnail_media_type       TEXT NOT NULL,
    ocr_blob_hash              TEXT NOT NULL,
    caption_blob_hash          TEXT NOT NULL,
    thumbnail_tool             TEXT NOT NULL,
    thumbnail_tool_version     TEXT NOT NULL,
    ocr_tool                   TEXT NOT NULL,
    ocr_tool_version           TEXT NOT NULL,
    caption_tool               TEXT NOT NULL,
    caption_model              TEXT NOT NULL,
    caption_model_version      TEXT NOT NULL,
    locality                   TEXT NOT NULL CHECK (locality IN ('local', 'cloud')),
    cloud_opt_in               INTEGER NOT NULL DEFAULT 0 CHECK (cloud_opt_in IN (0, 1)),
    created_at                 TEXT NOT NULL,
    UNIQUE (
        artifact_version_id,
        thumbnail_tool, thumbnail_tool_version,
        ocr_tool, ocr_tool_version,
        caption_tool, caption_model, caption_model_version,
        locality
    )
);

CREATE INDEX idx_image_derivations_version
    ON image_derivations(artifact_version_id, created_at);
