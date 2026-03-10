# Issues by Asset Type — Code Missing (Diagnosis & Fix)

## Problem

The "Issues by Asset Type" dashboard widget showed only **Container** and **Package**, with **Code** absent, despite having code findings (e.g. from Aikido SAST, Semgrep, Gitleaks).

## Root Cause

The misreporting came from **asset type classification** in `getAssetTypeFromAsset` (`frontend/lib/assetUtils.ts`):

1. **Code repos** (SAST, Secret, IaC) from Aikido often have `image` set (repo identifier like `org/repo`) but **no `branch`**.
2. The original logic treated any asset with `hasImage` as **container** when `hasBranch` was false:
   ```ts
   if (hasImage && hasBranch) return "repo";   // code
   if (hasImage) return "container";           // ← code repos fell here
   ```
3. Those assets were placed in `containerAssets` instead of `repoAssets` in `toVATDashboardData`.
4. `computeAssetMix` uses `repos` for Code and `containers` for Container. Code repo names were in the containers list, so issues were classified as **Container** instead of **Code**.

## Data Flow

```
findings → deriveAssets() → assets (no type)
                ↓
        getAssetTypeFromAsset(asset)
                ↓
    repo / container / package / path
                ↓
    toVATDashboardData: repoAssets vs containerAssets
                ↓
    computeAssetMix(issues, repos, containers, vms)
                ↓
    Code count = issues matching repos (and not looksLikePackageOrPath)
```

## Fix

### 1. Image + code finding type (Aikido code with repo but no branch)

```ts
if (hasImage && isCodeFinding) return "repo";
```

### 2. File path + code finding type (Aikido code keyed by component)

When Aikido omits `code_repo_name`, the asset is keyed by `component` (e.g. file path or rule id) and `image` is empty. These were misclassified as **package**:

```ts
if (hasFilePath && isCodeFinding) return "repo";
```

### Backend alignment

`assets_service._infer_asset_type_from_findings` was updated to use `findingType` and `filePath` so API-returned assets match frontend classification.

## Files Changed

- `frontend/lib/assetUtils.ts` — `CODE_FINDING_TYPES`, `hasImage && isCodeFinding`, `hasFilePath && isCodeFinding`
- `backend/app/services/assets_service.py` — same logic in `_infer_asset_type_from_findings`

## Verification

The "Issues by Asset Type" widget should show **Code** when you have open SAST, Secret, or IaC findings from Aikido, whether they have `image` (repo) or are keyed by `component` with `file_path`.
