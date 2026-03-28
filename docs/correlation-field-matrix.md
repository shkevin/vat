# Correlation field matrix

**Status:** Active — describes current backend behavior after Phases B–C (`v1:` correlation keys, SARIF partial fingerprints, identity strategies). See [`implementation-plan-dedup-correlation-hardening.md`](implementation-plan-dedup-correlation-hardening.md).

**Layers**

| Layer | Purpose | Primary implementation |
|-------|---------|-------------------------|
| **Fingerprint** (`fingerprint_id`) | Replay dedup — same scanner finding instance re-imported | `app/services/ingest_identity.py` (`compute_ingest_fingerprint`, strategies) |
| **Correlation key** (`correlation_key`) | Cross-source / cross-parser linking | `app/services/correlation.py` (`correlation_key_for_payload`) |
| **Grouping key** | Derived actionable group (read-time, not stored) | `app/services/grouping.py` (`get_finding_group_key`); frontend: `findingGroupUtils` |

**Normalization:** CVE and string casing for keys use `identity_normalization.normalize_cve_id` and `dedup.normalize` / `dedup.component_base` where applicable.

---

## Matrix by finding type

Columns summarize **which inputs** feed each layer. Empty cells mean that layer does not use that field for that type (or uses a fixed fallback).

| Finding type | Fingerprint (dedup) — main inputs | Correlation key — main shape | Grouping key — main shape | Notes |
|--------------|-------------------------------------|------------------------------|-----------------------------|--------|
| **SCA** | CVE + `component`/`component_base` + `image` + `branch` + `tag` + `source_name` via `make_fingerprint`; or `source_issue_id`; or static/SARIF branches if mis-typed | `v1:sca:{image\|branch\|tag}:{ecosystem}:{component_base}:{cve}` (high) or `v1:sca:{asset}:{cve}` without component (medium) | `sca:{eco}\|{pkg}#{image\|branch\|tag}` or CVE fallback | Ecosystem + package normalized for grouping (`normalize_package_name`). Optional **`VAT_CORRELATION_INCLUDE_DIGEST`**: appends `:digest:{normalized}` to correlation inner when digest present. |
| **License** | Same default chain as SCA unless overridden | Same branches as SCA (`ft` `license`) | `license:{eco}\|{pkg}#{asset}` | Grouping aligns with SCA-style package identity. |
| **SAST** | Resolved SARIF `partial_fingerprints` hash → SHA256 material; else `scanner_identity`; else `rule_id` + `file_path` + `line` + `snippet` + source | `v1:sast:{asset}:{rule}:{path}` or with `:fp:{hash}` when partial FP resolved; rule-only fallback (low) | `sast:{rule\|cwe\|title}#{asset}` | Correlation prefers stable FP segment when rule+path present. |
| **IaC** | Same static chain as SAST | `v1:iac:{asset}:{rule}:{path}` or variants | `iac:{rule\|title}#{asset}` | |
| **Secret** | Same static chain as SAST | `v1:secret:{asset}:{rule}:{path}` or CVE fallback | `secret:{type\|rule\|title}#{asset}` | Grouping keeps location in title for secrets when needed. |
| **OpenSCAP / compliance-style** | When `stable_rule_key` + asset and source is `openscap` / `openscap_oval`: `make_openscap_fingerprint` (benchmark family, profile, rule key); else falls through default chain | If mapped to a non-SCA type in VAT schema, follows that branch; generic payloads may fall under `v1:other:…` | Compliance-oriented groups use rule/title patterns in `grouping.py` for non-SCA | Fingerprint is specialized; correlation typing depends on emitted `finding_type`. |

---

## Cross-cutting behaviors

| Topic | Behavior |
|-------|----------|
| **Key version** | All new `correlation_key` values use prefix `v1:` (`CORRELATION_KEY_VERSION`). |
| **Asset segment** | `image\|branch\|tag` — normalized components joined with `\|` (see `correlation_key_for_payload`). **`image` in this segment** is `correlation_asset_image_for_ingest`: canonical container registry path when the ref is container-like, then `asset_aliases` chain (`resolve_canonical_asset_id`). Branch/tag are still from the payload at ingest time. HTTP ingest also rewrites `payload.image` upstream; service-layer correlation keeps non-HTTP entry points (sync/webhooks) aligned. |
| **Container digest** | Stored on `Finding.image_digest`; optional **digest suffix** on SCA/license correlation keys when `VAT_CORRELATION_INCLUDE_DIGEST=true`. |
| **Digest conflicts** | Recorded in `asset_digest_conflicts`; asset list/detail exposes `digestConflictOpen` / `digestConflicts` for UI (see `assets_service`, `GET .../digest-conflicts`). |

---

## References

- `app/services/ingest_identity.py` — fingerprint precedence (§4.6 plan).
- `app/services/sarif_fingerprints.py` — partial fingerprint precedence (§4.5).
- `app/services/correlation.py` — typed correlation keys.
- `app/services/grouping.py` — grouping keys.
- [`correlation-linking-architecture.md`](correlation-linking-architecture.md) — linking policy and ops flags.
