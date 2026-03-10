# Finding Location Diagnosis — Where Things Were Found

## Problem

Findings in kamiwaza-bundle show COMPONENT, ASSET, and LOCATION all as "kamiwaza-bundle" with no indication of:
- **Which container image** within the bundle had the finding (e.g. kamiwaza-images-core-release-0.11.0)
- **Which file path** within that image (e.g. /app/config/key.pem for secrets)

## Current Flow

### 1. Scanner (vat-local-scanner)

**normalize_trivy** (scan.py → normalize.py):
- Sets `Target = asset_name` (kamiwaza-bundle) for all Results
- Adds `_vat_source_image = src.label` (e.g. kamiwaza-images-core-release-0.11.0) per Result
- **Issue**: Trivy container scan may have a different structure — Result.Target from Trivy could be image digest; we overwrite it

**Trivy JSON structure** (container image scan):
- `Results[]` — one per layer or per image
- Each Result: `Target` (image ref or path), `Secrets`, `Vulnerabilities`, etc.
- **Secrets**: Trivy fanal has `Secret { FilePath, Findings[] }` — so Secrets may be `[{ FilePath, Findings: [...] }]` (nested) or flattened `[{ RuleID, Category, ... }]`
- Per-secret path: `Target`, `File`, `FilePath` at secret level (gating.py uses `v.get("Target") or v.get("File") or v.get("file")`)

### 2. Backend Parser (trivy.py)

**_parse_secrets**:
- Uses `file_path = (source_image or target)` — same for ALL secrets in the Result
- **Does NOT extract** per-secret `Target`, `File`, `FilePath` from each secret
- **Does NOT** handle nested `Secrets: [{ FilePath, Findings }]` structure

**_parse_vulnerabilities**:
- Uses `file_path = (source_image or target)` — source_image is the container label ✓
- Component = package name (e.g. go.opentelemetry.io/otel/sdk v1.36.0) ✓

### 3. Asset Type Transform (ingest.py)

When `asset_type=package`:
- If `img and comp and img != comp` → preserve (container + package)
- Else: `image=None`, `component=asset_val`, `tag=asset_val`
- **For secrets**: component=None, so we fall into "else" → we overwrite and set component=kamiwaza-bundle, clearing image. That loses the container context for display.

### 4. Frontend Display

- **Finding Scope**: COMPONENT, ASSET, LOCATION
- LOCATION comes from `formatFileLocation(finding) ?? finding.filePath ?? finding.component`
- If file_path is set to source_image, it should show. If component was overwritten to kamiwaza-bundle, that might be used as fallback.

## Root Causes

1. **Trivy secret structure**: Parser may not handle Trivy's actual JSON — need to support both:
   - Flat: `Secrets: [{ RuleID, Target?, File?, FilePath?, ... }]`
   - Nested: `Secrets: [{ FilePath, Findings: [{ RuleID, ... }] }]`

2. **Per-secret file path**: Parser uses one file_path for all secrets in a Result. Should extract per-secret path.

3. **file_path composition**: For container bundle scans, file_path should be: `{source_image}:{secret_file_path}` or `{source_image}` when no per-secret path.

4. **Asset transform**: For findings with image but no component (secrets), the transform overwrites image→component. We should preserve image when it's the bundle asset.

## Implemented Fixes

### Fix 1: Trivy parser — per-secret path and nested structure ✓

**backend/app/parsers/trivy.py**:
- Support Trivy fanal nested structure: `Secrets: [{ FilePath, Findings: [...] }]`
- For each secret, extract path from `FilePath`, `Target`, `File`, `file`
- Build `file_path`: `{source_image}:{path}` when both present, else `source_image` or `path`
- Set `line` from `StartLine` when available
- Misconfigurations: per-item `Path`, `FilePath`, `Target`, `File` when available

### Fix 2: Normalize — _vat_source_image ✓ (already done)

Scanner injects `_vat_source_image` per Result; parser reads it for `file_path`.

### Fix 3: Re-scan required

Existing findings in the DB retain old `file_path`. Re-scan with `vat-local-scanner` and push to ingest new findings with correct location.
