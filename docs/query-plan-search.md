# Hot-path query plan — policy-filtered retrieval

Tessera performs policy-filtered semantic retrieval in **one SQL statement**:
the sqlite-vec KNN scan joined against the artifact/space/tag/media/sensitivity
constraints compiled from a lens, plus the non-overridable `state = 'live'`
quarantine predicate. This document records the reviewed
`EXPLAIN QUERY PLAN` for that statement (issue #19).

The SQL is built by `SqliteVecIndex::build_search_sql`
(`crates/tessera-core/src/index/sqlite_vec.rs`). The plan below is captured
against a fully-loaded lens (space include + exclude, tag include + exclude,
media type, sensitivity ceiling) so every optional predicate branch is present.
The test `hot_path_uses_knn_and_indexed_joins` regenerates this plan and fails
if any base table starts being fully scanned.

## Reviewed plan

```
SCAN chunk_embeddings VIRTUAL TABLE INDEX 0:3{___}___
SEARCH em USING INDEX sqlite_autoindex_embeddings_map_2 (vec_rowid=?)
SEARCH ch USING INDEX sqlite_autoindex_chunks_1 (id=?)
SEARCH dt USING INDEX sqlite_autoindex_derived_text_1 (id=?)
SEARCH av USING INDEX sqlite_autoindex_artifact_versions_1 (id=?)
SEARCH a USING INDEX sqlite_autoindex_artifacts_1 (id=?)
CORRELATED SCALAR SUBQUERY 2
SEARCH t USING INDEX sqlite_autoindex_tags_2 (name=?)
SEARCH at USING COVERING INDEX sqlite_autoindex_artifact_tags_1 (artifact_id=? AND tag_id=?)
CORRELATED SCALAR SUBQUERY 3
SEARCH t USING INDEX sqlite_autoindex_tags_2 (name=?)
SEARCH at USING COVERING INDEX sqlite_autoindex_artifact_tags_1 (artifact_id=? AND tag_id=?)
USE TEMP B-TREE FOR ORDER BY
```

## Why this is the shape we want

- **KNN drives the query.** `SCAN chunk_embeddings VIRTUAL TABLE` is the
  sqlite-vec `MATCH ... AND k = ?` scan and is the leftmost (driving) table.
  The vector index bounds the candidate set to `knn_k` rows *before* the
  metadata joins run, so filtering is proportional to the KNN fan-out, not the
  size of the vault.
- **Every join is index-backed.** `em → ch → dt → av → a` are each a
  `SEARCH ... USING INDEX (id=?)` on a primary-key / unique autoindex. No base
  metadata table is scanned in full.
- **Tag include/exclude are covered subqueries.** Each `EXISTS` /
  `NOT EXISTS` resolves through the `tags(name)` unique index and the
  `artifact_tags` covering index — no scan of the tag tables.
- **The only sort is over the candidate set.** `USE TEMP B-TREE FOR ORDER BY`
  orders at most `knn_k` already-filtered rows by distance; it is not a sort of
  the full corpus.

## Over-fetch ladder

`search` starts with `knn_k = clamp(k*4, 64, 4096)` and, only if the policy
join under-fills `k`, widens `knn_k` (×4) and re-runs the *same* single
statement. Each attempt is one KNN+join query; the ladder is a fallback, not
the common path.
