# VAT Modern UI Token Map (v2)

Date: 2026-04-01  
Style target: Balanced enterprise modern

## Goals

- Preserve existing `data-theme` contract and current theme IDs.
- Introduce semantic aliases so components stop depending on raw `--app-*` names.
- Move toward consistent spacing, radius, shadow, and motion primitives.

## Semantic Token Layers

### Surface and text

| Semantic token | Current source |
| --- | --- |
| `--ui-surface-app` | `--app-bg` |
| `--ui-surface-1` | `--app-card-bg` |
| `--ui-surface-2` | `--app-input-bg` |
| `--ui-surface-header` | `--app-header-bg` |
| `--ui-surface-pane-header` | `--app-pane-header-bg` |
| `--ui-text-primary` | `--app-fg` |
| `--ui-text-secondary` | `--app-fg-secondary` |
| `--ui-text-muted` | `--app-muted` |
| `--ui-text-group` | `--app-fg-group` |

### Interactive and status

| Semantic token | Current source |
| --- | --- |
| `--ui-accent` | `--app-accent` |
| `--ui-accent-strong` | `--app-accent-emerald` |
| `--ui-danger` | `--app-danger` |
| `--ui-success` | `--app-success` |
| `--ui-warning` | `--app-warning` |
| `--ui-border` | `--app-border` |
| `--ui-border-subtle` | `--app-border-subtle` |
| `--ui-header-border` | `--app-header-border` |
| `--ui-focus-ring` | `--app-accent-emerald` |

### Layout and density

| Semantic token | Value |
| --- | --- |
| `--space-1` | `4px` |
| `--space-2` | `8px` |
| `--space-3` | `12px` |
| `--space-4` | `16px` |
| `--space-5` | `20px` |
| `--space-6` | `24px` |
| `--radius-sm` | `6px` |
| `--radius-md` | `10px` |
| `--radius-lg` | `14px` |
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.2)` |
| `--shadow-md` | `0 6px 24px rgba(0,0,0,0.25)` |
| `--motion-fast` | `140ms` |
| `--motion-base` | `200ms` |

## Migration Sequence

1. Add semantic aliases in `frontend/app/globals.css` while preserving all legacy tokens.
2. Extend Tailwind tokens in `frontend/tailwind.config.ts` to mirror aliases.
3. Migrate shell components first (`AppBanner`, `VATLayout`, `FilterSidebar`).
4. Migrate core workflow surfaces (`AssetsTable`, `ReviewQueue`, `DetailPanel`).
5. Apply consistency updates to secondary tabs (`Metrics`, `Report`, `Settings`, `Feeds`).
6. Remove duplicate inline styles once class-based styles cover each surface.

## Guardrails

- Keep all existing theme IDs: `vat`, `default`, `kamiwaza`, `light`, `slate`, `dracula`, `nord`, `catppuccin`, `tokyo-night`.
- Preserve classification color semantics and status color intent.
- Maintain keyboard focus visibility and 24px minimum interactive target size for controls.
- Do not introduce heavy animation that impairs dense review workflows.
