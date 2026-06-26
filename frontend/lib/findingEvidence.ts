import type { Finding } from "@/types";
import { formatFileLocation } from "./repoFileUrl";

export type FindingEvidenceSummaryRow = {
  label: string;
  value: string;
  href?: string;
};

export type FindingEvidenceProof = {
  label: string;
  language?: "text" | "yaml" | "shell" | "json";
  content: string;
  masked: boolean;
};

export type FindingEvidenceView = {
  summary: FindingEvidenceSummaryRow[];
  proof?: FindingEvidenceProof;
  explanation?: string;
  remediation?: string;
  references: FindingEvidenceSummaryRow[];
  warnings: string[];
};

function clean(value: string | null | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

function addRow(
  rows: FindingEvidenceSummaryRow[],
  label: string,
  value: string | null | undefined,
  href?: string | null,
) {
  const cleaned = clean(value);
  if (!cleaned) return;
  const row: FindingEvidenceSummaryRow = { label, value: cleaned };
  const cleanedHref = clean(href);
  if (cleanedHref) row.href = cleanedHref;
  rows.push(row);
}

function findingType(finding: Finding): string {
  return clean(finding.findingType)?.toLowerCase() ?? "";
}

function sourceName(finding: Finding): string | undefined {
  return clean(finding.source) ?? clean(finding.sources?.[0]?.name);
}

function isOpenScap(finding: Finding): boolean {
  const source = sourceName(finding)?.toLowerCase() ?? "";
  return (
    source.includes("openscap") ||
    Boolean(clean(finding.benchmarkId) || clean(finding.benchmarkFamily))
  );
}

function imageLabel(finding: Finding): string | undefined {
  const image = clean(finding.image);
  if (!image) return undefined;
  const tag = clean(finding.tag);
  if (!tag || image.endsWith(`:${tag}`)) return image;
  return `${image}:${tag}`;
}

function remediationFor(finding: Finding): string | undefined {
  if (isOpenScap(finding)) {
    return "Review the benchmark rule, apply the required configuration change, and rescan the host or image.";
  }
  const type = findingType(finding);
  if (type === "sca" || type === "license") {
    return "Upgrade or replace the affected package in the image, rebuild it, and rescan the asset.";
  }
  if (type === "iac") {
    return "Update the affected configuration, redeploy it, and rescan the object.";
  }
  if (type === "sast") {
    return "Review the affected code path, apply the rule-specific fix, and rescan the repository.";
  }
  return undefined;
}

function proofFor(finding: Finding): FindingEvidenceProof | undefined {
  const snippet = clean(finding.snippetMasked);
  if (!snippet) return undefined;
  if (isOpenScap(finding)) {
    return {
      label: "Check output",
      language: "text",
      content: snippet,
      masked: false,
    };
  }
  return {
    label: "Masked line preview",
    language: "text",
    content: snippet,
    masked: true,
  };
}

export function buildFindingEvidence(finding: Finding): FindingEvidenceView {
  const summary: FindingEvidenceSummaryRow[] = [];
  const references: FindingEvidenceSummaryRow[] = [];
  const warnings: string[] = [];
  const type = findingType(finding);
  const location = formatFileLocation(finding);

  addRow(summary, "Location", location, finding.sourceFileUrl);
  addRow(summary, "Package", finding.component);
  addRow(summary, "Image", imageLabel(finding));
  addRow(summary, "Image digest", finding.imageDigest);
  addRow(summary, "Resource", finding.resource);
  addRow(summary, "Rule", finding.ruleId);
  addRow(summary, "CWE", finding.cweId);
  addRow(summary, "Secret type", finding.secretType);
  addRow(summary, "Ecosystem", finding.ecosystem);
  addRow(summary, "Benchmark", finding.benchmarkId);
  addRow(summary, "Benchmark family", finding.benchmarkFamily);
  addRow(summary, "CVSS", finding.cvss);
  addRow(summary, "EPSS", finding.epss);
  addRow(summary, "Source", sourceName(finding));

  const sourceLink = finding.externalLinks?.find(
    (link) => link.kind === "source" && clean(link.url),
  );
  if (sourceLink?.url) {
    addRow(references, "View in source", sourceLink.url, sourceLink.url);
  }
  if (clean(finding.sourceFileUrl)) {
    addRow(references, "Source file", finding.sourceFileUrl, finding.sourceFileUrl);
  }

  if (type === "secret") {
    warnings.push("Rotate the exposed credential and verify it has not been used.");
  }

  return {
    summary,
    proof: proofFor(finding),
    explanation: clean(finding.description),
    remediation: remediationFor(finding),
    references,
    warnings,
  };
}
