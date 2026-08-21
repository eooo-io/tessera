# Local model supply chain and portability

Tessera installs two pinned local models: the embedder that defines the query
space, and the vision-language model that captions images. Both are bound by
repository-controlled manifests and verified byte-for-byte before loading. The
sections below describe the embedder first; the caption model follows the same
rules and is covered under [Image captioning model](#image-captioning-model).

Tessera v1 accepts one query-compatible embedding space:
`all-MiniLM-L6-v2@onnx-1`, 384 dimensions. This is a versioned compatibility
contract, not a suggestion. A different model, tokenizer, dimension, or
uncalibrated revision is forbidden until a future vault-format/index migration
defines a new space. Automatic upgrades and silent query-time downloads are
deliberately absent.

## Trust root and installed assets

The repository-controlled manifest is
[`spec/model-manifests/all-MiniLM-L6-v2-onnx-1.json`](../spec/model-manifests/all-MiniLM-L6-v2-onnx-1.json).
It binds:

- the upstream Sentence Transformers repository and immutable Git revision;
- every runtime file's path, byte length, and SHA-256 digest;
- Apache-2.0 license, 384-dimensional output, tokenizer limit, and runtime;
- Tessera's exact model-version identifier.

This distinguishes three facts that should not be mushed into one vague
"model available" flag:

1. The trusted manifest defines what this Tessera build can query.
2. `tessera.json` records the exact model versions that produced a vault's
   active vectors.
3. `tessera model status` verifies whether compatible local assets are actually
   installed on this host.

`tessera model fetch` downloads from the immutable revision into a sibling
staging directory. Tessera checks sizes and SHA-256 digests before activation,
then switches the verified directory into place. Failed downloads, corrupted
bytes, substituted tokenizer files, or activation errors leave the last
working installation intact. `OnnxEmbedder::load` repeats verification before
ONNX Runtime sees the files; a stale `models.lock` cannot authorize anything.

Owner-visible source, revision, license, runtime, path, and verification state
for every installed model:

```bash
tessera model status                    # both models
tessera model status --model embedding  # just the query space
```

## Offline and cross-host provisioning

On an online machine, fetch and verify the model, then copy the entire verified
model directory over an authenticated medium. The defaults are:

- macOS: `~/Library/Application Support/tessera/models/all-MiniLM-L6-v2`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/tessera/models/all-MiniLM-L6-v2`

On the offline or copied-to host, do not copy files directly into the active
directory. Stage, verify, and atomically install them:

```bash
# Linux example; --vault is only needed for vault/index commands.
tessera model install --source /media/verified/all-MiniLM-L6-v2
tessera model install --model caption \
  --source /media/verified/vit-gpt2-image-captioning
tessera model status
tessera --vault /srv/V.tessera query "owner question"
```

`TESSERA_MODEL_DIR=/controlled/model/root` overrides the platform root; Tessera
appends the model name. A macOS-created `.tessera` bundle itself is portable to
Linux. The model is not bundled because it is a separately licensed, replaceable
runtime asset; query fails closed with both online and offline recovery commands
when the compatible asset is absent.

## Resumable non-destructive reindex

Reindex builds `reindex_chunk_embeddings` and its durable map beside the active
index. Each completed chunk commits independently. Interruption, a bounded
maintenance pause, or cooperative cancellation preserves both progress and the
last working active index. Only a complete shadow index is copied into the
active tables inside one SQLite transaction; any activation failure rolls back.

```bash
# Start or resume. Omit --max-chunks for an uninterrupted run.
tessera --vault /srv/V.tessera model reindex --max-chunks 100
tessera --vault /srv/V.tessera model reindex-status
tessera --vault /srv/V.tessera model reindex-cancel
tessera --vault /srv/V.tessera model reindex  # resume and atomically activate
```

Cancellation is cooperative between chunks. Re-running `reindex` explicitly
resumes a cancelled compatible run. A partial run for another model version is
refused, and the fixed 384-dimensional table rejects any other dimensions.

Receipts bind the exact `model_version` used for semantic retrieval. Copying a
vault does not weaken that binding: missing or incompatible local assets stop
the query before disclosure.

## Image captioning model

Image understanding adds a second pinned asset:
`vit-gpt2-image-captioning@onnx-1`, manifested at
[`spec/model-manifests/vit-gpt2-image-captioning-onnx-1.json`](../spec/model-manifests/vit-gpt2-image-captioning-onnx-1.json).
It is the Apache-2.0 ONNX export of `nlpconnect/vit-gpt2-image-captioning`,
pinned to an immutable upstream revision and bound by the same size and
SHA-256 checks the embedder uses — `verify_files` is one shared implementation,
not two parallel ones.

The quantized encoder and the *unmerged* decoder are pinned deliberately. The
unmerged export takes only `input_ids` and `encoder_hidden_states`, so greedy
decoding needs no key/value cache plumbing, and greedy decoding in turn keeps a
derivation reproducible: the same pixels must always yield the same caption or
image derivations stop being idempotent.

```bash
tessera model fetch                   # both models
tessera model fetch --model caption   # captions only (~245 MB)
tessera model status --model caption
```

Defaults are siblings of the embedder:

- macOS: `~/Library/Application Support/tessera/models/vit-gpt2-image-captioning`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/tessera/models/vit-gpt2-image-captioning`

OCR is not a downloaded asset. It runs through the macOS Vision framework, so
its provenance records the recognizer *revision* and OS version rather than a
digest — recognition output changes between revisions, and a derivation is only
reproducible against the revision that produced it. Off macOS, image
understanding fails closed with an explicit reason instead of silently
producing captions with no recognized text.

Captions and OCR text are the searchable surface for images: they become one
`derived_text` row, chunked and embedded like any document. An image with
neither is refused rather than stored as an unsearchable derivation. Cloud
captioning stays refused unless the owner opts that exact item in, and the
refusal happens before the encrypted original is decrypted.
