import type { ApiFinding } from "@/lib/api";
import type { Finding } from "@/types";

export function toDetailFinding(raw: ApiFinding): Finding {
  return {
    ...(raw as unknown as Finding),
    source: raw.source ? String(raw.source) : undefined,
    component: raw.component ? String(raw.component) : undefined,
    image: raw.image ? String(raw.image) : undefined,
    branch: raw.branch ? String(raw.branch) : undefined,
    tag: raw.tag ? String(raw.tag) : undefined,
    description: raw.description ? String(raw.description) : undefined,
    filePath: raw.filePath ? String(raw.filePath) : undefined,
    line: typeof raw.line === "number" ? raw.line : undefined,
    snippetMasked: raw.snippetMasked ? String(raw.snippetMasked) : undefined,
    sourceFileUrl: raw.sourceFileUrl ? String(raw.sourceFileUrl) : undefined,
    audit: Array.isArray(raw.audit) ? (raw.audit as Finding["audit"]) : [],
    sources: Array.isArray(raw.sources) ? (raw.sources as Finding["sources"]) : [],
    externalLinks: Array.isArray(raw.externalLinks)
      ? (raw.externalLinks as Finding["externalLinks"])
      : undefined,
  };
}

export function chooseFindingForDetail(
  selected: Finding | null | undefined,
  selectedDetail: Finding | null | undefined,
): Finding | null {
  if (!selected) return null;
  if (!selectedDetail || selectedDetail.id !== selected.id) return selected;

  const selectedAuditCount = selected.audit?.length ?? 0;
  const detailAuditCount = selectedDetail.audit?.length ?? 0;
  if (selectedAuditCount > detailAuditCount) return selected;

  return selectedDetail;
}
