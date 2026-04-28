# Cross-source container deduplication (runbook)

This note covers when the **same logical container** appears as **different assets** because sources use different registry paths (for example scanner `containers/images/...` vs integration `operators/images/...`), and how to align identity safely.

## 1. Prefer digest-first identity

- **Manifest digest** (`sha256:…`) is the strongest join key across sources. Ensure findings carry `image_digest` where possible (local scanner payloads, Aikido export fields, ingest).
- Use **Asset Merge Review** in the UI: high-confidence **digest** suggestions are highlighted on the asset page when available. Approve there before grouping assets.

## 2. Path prefix equivalence (tenant policy)

When two paths are **policy-equivalent** (same org policy, different path prefixes), set:

- **Backend:** `VAT_CONTAINER_ASSET_PATH_ALIASES` — semicolon-separated pairs  
  `source_prefix=>target_prefix`  
  Applied **after** `normalize_container_ref`, on the **lowercase** canonical key for matching; the returned key keeps the original casing of the suffix after `source_prefix`.  
  **Empty `target_prefix`** (nothing after `=>`, or whitespace only) means **strip** `source_prefix` so multiple registry shapes collapse to one bare key (e.g. `containers/images/python`).  
  Example (rewrite only):  
  `docker.io/operators/images/=>docker.io/containers/images/`  
  Example (strip registries for online ↔ offline parity):  
  `docker.io/=>;ghcr.io/kamiwaza-internal/=>;registry-1.docker.io/=>`

- **Frontend (grouping parity):** `NEXT_PUBLIC_VAT_CONTAINER_ASSET_PATH_ALIASES` — same syntax so sidebar grouping matches the API.

Do not use this for unrelated images that only share a **last path segment**; prefer digest or explicit review.

## 3. Manual `asset_aliases`

When digest is missing and path aliases are wrong or insufficient, use the product’s **asset alias** flow (admin) so `resolve_canonical_asset_id` maps both IDs to one canonical asset. Keep merges **reviewed** and documented.

## 4. Operational checklist

1. Confirm ingest populates **digest** for target images where the source provides it.
2. Check **merge suggestions** (digest strategy) on the asset **Review** tab.
3. If paths differ by prefix only, add **path aliases** (backend + frontend) and redeploy.
4. Approve merge review, then **group/merge** as your process requires.
5. Watch **digest conflict** signals on the same tab before approving risky merges.

## 5. Related code

- `backend/app/services/container_ref_normalization.py` — `apply_container_asset_path_aliases`
- `frontend/lib/containerRefNormalization.ts` — `applyContainerAssetPathAliases`
- `backend/app/adapters/aikido.py` — `image_digest` on `VatFindingSchema`
