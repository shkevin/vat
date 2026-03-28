/**
 * Client-side full export bundle — assets, findings, SBOM (CycloneDX), and Executive Summary report.
 * Uses the report engine's executive-detailed-yearly-instances preset for correct template.
 * JSZip is dynamically imported to avoid SSR/module resolution issues.
 */
import { fetchSbomPackages, fetchVATData } from "@/lib/api";
import {
  REPORT_PRESETS,
  buildReportHtmlFromDefinition,
  clonePresetDefinition,
  computeReportContext,
} from "@/lib/report/report-engine";
import { toVATDashboardData } from "@/lib/report/vatReportAdapter";
import type { Asset, Finding } from "@/types";
import type { Auth } from "@/lib/api";

function languageToPurlType(lang: string): string {
  const l = (lang ?? "").toLowerCase();
  if (l.includes("java") || l === "java") return "maven";
  if (
    l.includes("js") ||
    l.includes("ts") ||
    l === "javascript" ||
    l === "typescript"
  )
    return "npm";
  if (l.includes("py") || l === "python") return "pypi";
  if (l.includes("go")) return "golang";
  if (l.includes("rust")) return "cargo";
  if (l.includes("ruby")) return "gem";
  if (l.includes("php")) return "composer";
  if (l.includes("c") || l.includes("c++")) return "generic";
  return "generic";
}

/** Derive CycloneDX supplier from purl type (per package ecosystem). */
function supplierFromPurlType(purlType: string): { name: string } | undefined {
  const m: Record<string, string> = {
    npm: "npm",
    pypi: "PyPI",
    maven: "Maven Central",
    golang: "Go Modules",
    cargo: "crates.io",
    gem: "RubyGems",
    composer: "Packagist",
    nuget: "NuGet",
  };
  const name = m[purlType];
  return name ? { name } : undefined;
}

interface SBOMPackageForExport {
  id: string;
  name: string;
  version: string;
  license: string;
  component?: string;
  language?: string;
}

function toCycloneDX(packages: SBOMPackageForExport[]): object {
  const now = new Date().toISOString();
  const uuid =
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
          const r = (Math.random() * 16) | 0;
          const v = c === "x" ? r : (r & 0x3) | 0x8;
          return v.toString(16);
        });
  const purlType = languageToPurlType;

  const seenPurl = new Set<string>();
  const components = packages
    .map((p) => {
      const purlTypeVal = purlType(p.language ?? "");
      const ver = p.version || "0.0.0";
      const purl =
        purlTypeVal === "generic"
          ? `pkg:generic/${encodeURIComponent(p.name)}@${encodeURIComponent(
              ver,
            )}`
          : `pkg:${purlTypeVal}/${encodeURIComponent(
              p.name,
            )}@${encodeURIComponent(ver)}`;
      if (seenPurl.has(purl)) return null;
      seenPurl.add(purl);

      const comp: Record<string, unknown> = {
        type: "library",
        name: p.name,
        version: p.version || undefined,
        purl,
        licenses:
          p.license && p.license !== "Unknown"
            ? [{ license: { id: p.license } }]
            : undefined,
        language: p.language || undefined,
      };
      const supplier = supplierFromPurlType(purlTypeVal);
      if (supplier) comp.supplier = supplier;
      return comp;
    })
    .filter((c): c is Record<string, unknown> => c !== null);

  return {
    $schema: "http://cyclonedx.org/schema/bom-1.4.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.4",
    serialNumber: `urn:uuid:${uuid}`,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [{ vendor: "Compliance", name: "SBOM Export", version: "1.0" }],
    },
    components,
  };
}

function toFinding(raw: Record<string, unknown>): Finding {
  return {
    ...raw,
    id: String(raw.id),
    findingType: String(raw.findingType),
    cveId: String(raw.cveId),
    severity: String(raw.severity),
    status: String(raw.status),
    source: raw.source ? String(raw.source) : undefined,
    component: raw.component ? String(raw.component) : undefined,
    image: raw.image ? String(raw.image) : undefined,
    branch: raw.branch ? String(raw.branch) : undefined,
    tag: raw.tag ? String(raw.tag) : undefined,
    sources: Array.isArray(raw.sources)
      ? (raw.sources as Finding["sources"])
      : [],
    audit: Array.isArray(raw.audit) ? (raw.audit as Finding["audit"]) : [],
    regressionOf: Array.isArray(raw.regressionOf)
      ? (raw.regressionOf as string[])
      : undefined,
    regressionCount:
      typeof raw.regressionCount === "number" ? raw.regressionCount : 0,
    attestation: (raw.attestation as Finding["attestation"]) ?? null,
    archived: Boolean(raw.archived),
    slaDue: raw.slaDue ? String(raw.slaDue) : undefined,
    trackerId: raw.trackerId ? String(raw.trackerId) : undefined,
    trackerComment: Boolean(raw.trackerComment),
    team: raw.team ? String(raw.team) : undefined,
    owner: raw.owner ? String(raw.owner) : undefined,
    justification: raw.justification ? String(raw.justification) : undefined,
    sourceIssueGroupId: raw.sourceIssueGroupId
      ? String(raw.sourceIssueGroupId)
      : undefined,
    sourceGroupSeverity: raw.sourceGroupSeverity
      ? String(raw.sourceGroupSeverity)
      : undefined,
    filePath: raw.filePath ? String(raw.filePath) : undefined,
    line: typeof raw.line === "number" ? raw.line : undefined,
    snippetMasked: raw.snippetMasked ? String(raw.snippetMasked) : undefined,
    externalLinks: Array.isArray(raw.externalLinks)
      ? (raw.externalLinks as Finding["externalLinks"])
      : undefined,
  } as Finding;
}

/** Build and download the full export bundle using the report engine's Executive Summary template. */
export async function buildAndDownloadExportBundle(auth?: Auth): Promise<void> {
  const [vatRes, sbomRes] = await Promise.all([
    fetchVATData({ limit: 0, full: true, include_zero_assets: true }, auth),
    fetchSbomPackages({ limit: 10000 }, auth),
  ]);

  const findings = vatRes.findings.map((r) =>
    toFinding(r as unknown as Record<string, unknown>),
  );
  const assets: Asset[] = (vatRes.assets ?? []).map((a) => ({
    ...a,
    findings: (a.findings ?? []).map((r) =>
      toFinding(r as unknown as Record<string, unknown>),
    ),
  })) as Asset[];

  const packages: SBOMPackageForExport[] = Array.isArray(sbomRes)
    ? sbomRes.map((p) => ({
        id: p.id,
        name: p.name,
        version: p.version,
        license: p.licenseId ?? "",
        component: p.component ?? "",
        language: p.language ?? "",
      }))
    : [];

  const cyclonedx = toCycloneDX(packages);

  const preset = REPORT_PRESETS.find(
    (p) => p.id === "executive-detailed-yearly-instances",
  );
  const definition = preset ? clonePresetDefinition(preset) : null;

  let reportHtml = "";
  if (definition) {
    const data = toVATDashboardData(findings, assets, "VAT", {
      groupFindings: false,
    });
    const context = computeReportContext(data, definition.filters);
    reportHtml = buildReportHtmlFromDefinition(context, definition, {
      preview: false,
    });
  }

  const dateStr = new Date().toISOString().slice(0, 10);
  const JSZip = (await import("jszip")).default;
  const zip = new JSZip();
  const folder = zip.folder(`vat-export-${dateStr}`);
  if (!folder) throw new Error("Failed to create ZIP folder");

  folder.file(
    "assets-findings.json",
    JSON.stringify(
      { findings: vatRes.findings, assets: vatRes.assets },
      null,
      2,
    ),
  );
  folder.file("sbom-cyclonedx.json", JSON.stringify(cyclonedx, null, 2));
  folder.file(
    "executive-summary-yearly.html",
    reportHtml || "<html><body>Report not available</body></html>",
  );

  const blob = await zip.generateAsync({ type: "blob" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vat-export-${dateStr}.zip`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
