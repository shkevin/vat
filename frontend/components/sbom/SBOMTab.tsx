"use client";

import { useState, useMemo, useCallback } from "react";
import { mono } from "@/lib/styles";
import { LICENSE_RISK, SAMPLE_SBOM } from "@/lib/constants";
import type { Finding } from "@/types";

/** Map language hint to purl type for NTIA unique identifiers. */
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

/** Generate CycloneDX 1.4 JSON (standards-only, enterprise-friendly). */
function toCycloneDX(
  packages: SBOMPackage[],
  _findingCountByComponent: Map<string, number>,
  assetId: string | null | undefined,
): object {
  const now = new Date().toISOString();
  const uuid =
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
          const r = (Math.random() * 16) | 0;
          const v = c === "x" ? r : (r & 0x3) | 0x8;
          return v.toString(16);
        });
  const purlType = (lang: string) => languageToPurlType(lang);

  const seenPurl = new Set<string>();
  const components = packages
    .map((p) => {
      const purlTypeVal = purlType(p.language);
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
      ...(assetId && assetId !== "all"
        ? { component: { type: "application", name: assetId } }
        : {}),
    },
    components,
  };
}

/** Trigger browser download. format: cyclonedx = CycloneDX JSON (primary), csv = human-readable summary. */
function downloadDisplayedSbom(
  packages: SBOMPackage[],
  findingCountByComponent: Map<string, number>,
  format: "cyclonedx" | "csv",
  assetId: string | null | undefined,
) {
  const safeComponent = (assetId ?? "all").replace(/[/\\]/g, "-").slice(0, 50);
  const dateStr = new Date().toISOString().slice(0, 10);
  const ext = format === "cyclonedx" ? "json" : "csv";
  const filename = `sbom-${safeComponent}-${dateStr}.${ext}`;

  if (format === "cyclonedx") {
    const bom = toCycloneDX(packages, findingCountByComponent, assetId);
    const content = JSON.stringify(bom, null, 2);
    const blob = new Blob([content], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    return;
  }

  // CSV (human-readable summary for audits)
  const header = [
    "Package",
    "Version",
    "License",
    "License Risk",
    "Component",
    "Language",
    "Findings",
  ];
  const escape = (s: string) => {
    const str = String(s ?? "");
    return str.includes(",") || str.includes('"') || str.includes("\n")
      ? `"${str.replace(/"/g, '""')}"`
      : str;
  };
  const lines = [
    header.join(","),
    ...packages.map((p) =>
      [
        escape(p.name),
        escape(p.version),
        escape(p.license),
        escape(getLicenseRisk(p)),
        escape(p.component),
        escape(p.language),
        String(findingCountByComponent.get(p.id) ?? 0),
      ].join(","),
    ),
  ];
  const content = lines.join("\n");
  const blob = new Blob([content], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

interface SBOMPackage {
  id: string;
  name: string;
  version: string;
  license: string;
  licenseRisk?: string;
  component: string;
  language: string;
}

interface SBOMTabProps {
  sbom: SBOMPackage[];
  findings: Finding[];
  onImport?: (packages: SBOMPackage[]) => void;
  /** Asset/component name for download filename when set. */
  assetId?: string | null;
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"] as const;
const RISK_SORT_INDEX: Record<string, number> = Object.fromEntries(
  RISK_ORDER.map((r, i) => [r, i]),
);

function getLicenseRisk(pkg: Pick<SBOMPackage, "license" | "licenseRisk">): string {
  const backendRisk = (pkg.licenseRisk ?? "").trim();
  if (backendRisk === "Critical") return "Critical";
  if (backendRisk === "High") return "High";
  if (backendRisk === "Medium") return "Medium";
  if (backendRisk === "Low") return "Low";
  if (backendRisk === "Unknown") return "Unknown";
  return LICENSE_RISK[pkg.license] ?? "Unknown";
}

type SortKey =
  | "name"
  | "version"
  | "license"
  | "component"
  | "risk"
  | "findings";
type SortDir = "asc" | "desc";

function parseCycloneDX(jsonStr: string): SBOMPackage[] {
  try {
    const doc = JSON.parse(jsonStr);
    const components = doc.components ?? [];
    const seen = new Set<string>();
    return components
      .filter((c: { name?: string; version?: string }) => c.name && c.version)
      .map((c: Record<string, unknown>, i: number) => {
        const name = String(c.name ?? "");
        const version = String(c.version ?? "");
        const key = `${name}@${version}`;
        if (seen.has(key)) return null;
        seen.add(key);
        const licenses =
          (c.licenses as Array<{ license?: { id?: string } }>) ?? [];
        const license = licenses[0]?.license?.id ?? "Unknown";
        return {
          id: `sb-${i}-${name.slice(0, 8)}`,
          name,
          version,
          license,
          component: String(c.purl ?? "").split("/")[2] ?? "—",
          language: String((c as { type?: string }).type ?? "unknown"),
        };
      })
      .filter(Boolean) as SBOMPackage[];
  } catch {
    return [];
  }
}

export function SBOMTab({ sbom, findings, onImport, assetId }: SBOMTabProps) {
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [downloadLoading, setDownloadLoading] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("risk");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [searchText, setSearchText] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [licenseFilter, setLicenseFilter] = useState<string>("all");
  const [componentFilter, setComponentFilter] = useState<string>("all");
  const [findingsFilter, setFindingsFilter] = useState<
    "all" | "with" | "without"
  >("all");
  const [viewMode, setViewMode] = useState<"package" | "component" | "license">(
    "package",
  );

  const packages = sbom.length > 0 ? sbom : SAMPLE_SBOM;

  const findingCountByComponent = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) {
      // Extract package identifiers: componentBase (normalized), or first word of component (pkgName from "pkgName version"), or full component
      const compBase = (f as { componentBase?: string }).componentBase
        ?.trim()
        .toLowerCase();
      const comp = (f.component ?? "").trim().toLowerCase();
      const pkgNames: string[] = [];
      if (compBase) pkgNames.push(compBase);
      if (comp) {
        const firstWord = comp.split(/\s+/)[0];
        if (firstWord && !pkgNames.includes(firstWord))
          pkgNames.push(firstWord);
        if (comp !== firstWord && !pkgNames.includes(comp)) pkgNames.push(comp);
      }
      for (const pkg of packages) {
        const pkgName = (pkg.name ?? "").toLowerCase();
        if (!pkgName) continue;
        const matches = pkgNames.some(
          (pn) =>
            pn === pkgName || pn.includes(pkgName) || pkgName.includes(pn),
        );
        if (matches) {
          m.set(pkg.id, (m.get(pkg.id) ?? 0) + 1);
        }
      }
    }
    return m;
  }, [findings, packages]);

  const handlePaste = () => {
    const parsed = parseCycloneDX(pasteText);
    if (parsed.length > 0 && onImport) {
      onImport([...packages, ...parsed]);
    }
    setPasteText("");
    setPasteOpen(false);
  };

  const byRisk = useMemo(() => {
    const acc: Record<string, SBOMPackage[]> = {
      Critical: [],
      High: [],
      Medium: [],
      Low: [],
    };
    for (const p of packages) {
      const r = getLicenseRisk(p);
      if (acc[r]) acc[r].push(p);
    }
    return acc;
  }, [packages]);

  const distinctLicenses = useMemo(
    () =>
      Array.from(
        new Set(
          packages
            .map((p) => p.license?.trim())
            .filter((v): v is string => Boolean(v)),
        ),
      ).sort((a, b) => a.localeCompare(b)),
    [packages],
  );

  const distinctComponents = useMemo(
    () =>
      Array.from(
        new Set(
          packages
            .map((p) => p.component?.trim())
            .filter((v): v is string => Boolean(v)),
        ),
      ).sort((a, b) => a.localeCompare(b)),
    [packages],
  );

  const filteredPackages = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    return packages.filter((p) => {
      const risk = getLicenseRisk(p);
      const findingCount = findingCountByComponent.get(p.id) ?? 0;
      if (riskFilter !== "all" && risk !== riskFilter) return false;
      if (licenseFilter !== "all" && p.license !== licenseFilter) return false;
      if (componentFilter !== "all" && p.component !== componentFilter)
        return false;
      if (findingsFilter === "with" && findingCount <= 0) return false;
      if (findingsFilter === "without" && findingCount > 0) return false;
      if (!q) return true;
      const hay =
        `${p.name} ${p.version} ${p.license} ${p.component} ${p.language}`.toLowerCase();
      return hay.includes(q);
    });
  }, [
    packages,
    searchText,
    riskFilter,
    licenseFilter,
    componentFilter,
    findingsFilter,
    findingCountByComponent,
  ]);

  const sortedPackages = useMemo(() => {
    const arr = [...filteredPackages];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "risk") {
        const ra = getLicenseRisk(a);
        const rb = getLicenseRisk(b);
        cmp = (RISK_SORT_INDEX[ra] ?? 99) - (RISK_SORT_INDEX[rb] ?? 99);
        // Lower index = higher severity. desc = highest first = return cmp; asc = lowest first = return -cmp
        return sortDir === "desc" ? cmp : -cmp;
      }
      if (sortKey === "findings") {
        cmp =
          (findingCountByComponent.get(a.id) ?? 0) -
          (findingCountByComponent.get(b.id) ?? 0);
      } else if (sortKey === "name") {
        cmp = (a.name ?? "").localeCompare(b.name ?? "");
      } else if (sortKey === "version") {
        cmp = (a.version ?? "").localeCompare(b.version ?? "");
      } else if (sortKey === "license") {
        cmp = (a.license ?? "").localeCompare(b.license ?? "");
      } else if (sortKey === "component") {
        cmp = (a.component ?? "").localeCompare(b.component ?? "");
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [filteredPackages, sortKey, sortDir, findingCountByComponent]);

  const groupedRows = useMemo(() => {
    if (viewMode === "package") return [];
    const groups = new Map<
      string,
      {
        key: string;
        packages: SBOMPackage[];
        findings: number;
        worstRiskIndex: number;
      }
    >();
    for (const p of sortedPackages) {
      const key =
        viewMode === "component" ? p.component || "—" : p.license || "Unknown";
      const existing = groups.get(key) ?? {
        key,
        packages: [],
        findings: 0,
        worstRiskIndex: 99,
      };
      existing.packages.push(p);
      existing.findings += findingCountByComponent.get(p.id) ?? 0;
      existing.worstRiskIndex = Math.min(
        existing.worstRiskIndex,
        RISK_SORT_INDEX[getLicenseRisk(p)] ?? 99,
      );
      groups.set(key, existing);
    }
    return Array.from(groups.values()).sort((a, b) => {
      if (a.worstRiskIndex !== b.worstRiskIndex) {
        return a.worstRiskIndex - b.worstRiskIndex;
      }
      return b.findings - a.findings || b.packages.length - a.packages.length;
    });
  }, [sortedPackages, viewMode, findingCountByComponent]);

  const summary = useMemo(() => {
    const criticalOrHigh = sortedPackages.filter((p) => {
      const risk = getLicenseRisk(p);
      return risk === "Critical" || risk === "High";
    }).length;
    const withFindings = sortedPackages.filter(
      (p) => (findingCountByComponent.get(p.id) ?? 0) > 0,
    ).length;
    return {
      total: sortedPackages.length,
      uniqueLicenses: new Set(sortedPackages.map((p) => p.license || "Unknown"))
        .size,
      uniqueComponents: new Set(sortedPackages.map((p) => p.component || "—"))
        .size,
      criticalOrHigh,
      withFindings,
    };
  }, [sortedPackages, findingCountByComponent]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "risk" || key === "findings" ? "desc" : "asc");
    }
  };

  const handleDownload = useCallback(
    (format: "cyclonedx" | "csv") => {
      setDownloadLoading(true);
      try {
        downloadDisplayedSbom(
          sortedPackages,
          findingCountByComponent,
          format,
          assetId ?? undefined,
        );
      } finally {
        setDownloadLoading(false);
      }
    },
    [sortedPackages, findingCountByComponent, assetId],
  );

  const SortableHeader = ({
    label,
    colKey,
  }: {
    label: string;
    colKey: SortKey;
  }) => (
    <button
      type="button"
      onClick={() => handleSort(colKey)}
      style={{
        background: "none",
        border: "none",
        padding: 0,
        cursor: "pointer",
        textAlign: "left",
        width: "100%",
        display: "flex",
        alignItems: "center",
        gap: 4,
      }}
    >
      {label}
      {sortKey === colKey ? (sortDir === "asc" ? " ↑" : " ↓") : ""}
    </button>
  );

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 14,
        }}
      >
        <div
          style={{
            ...mono,
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: "0.12em",
            color: "var(--app-muted)",
            textTransform: "uppercase",
          }}
        >
          SBOM / Licenses
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            onClick={() => handleDownload("cyclonedx")}
            disabled={downloadLoading}
            style={{
              ...mono,
              background: "var(--app-accent)",
              border: "none",
              borderRadius: 4,
              padding: "6px 12px",
              color: "#fff",
              fontSize: 11,
              cursor: downloadLoading ? "not-allowed" : "pointer",
              opacity: downloadLoading ? 0.7 : 1,
            }}
          >
            {downloadLoading ? "Downloading…" : "Download CycloneDX"}
          </button>
          <button
            onClick={() => handleDownload("csv")}
            disabled={downloadLoading}
            style={{
              ...mono,
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 4,
              padding: "6px 12px",
              color: "var(--app-muted)",
              fontSize: 11,
              cursor: downloadLoading ? "not-allowed" : "pointer",
            }}
          >
            Download CSV
          </button>
          <button
            onClick={() => setPasteOpen(!pasteOpen)}
            style={{
              ...mono,
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 4,
              padding: "6px 12px",
              color: "var(--app-muted)",
              fontSize: 11,
              cursor: "pointer",
            }}
          >
            {pasteOpen ? "Cancel" : "Paste CycloneDX JSON"}
          </button>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
          gap: 10,
          marginBottom: 14,
        }}
      >
        {[
          { label: "Displayed Packages", value: String(summary.total) },
          { label: "Unique Licenses", value: String(summary.uniqueLicenses) },
          { label: "Components", value: String(summary.uniqueComponents) },
          { label: "Critical/High", value: String(summary.criticalOrHigh) },
          { label: "With Findings", value: String(summary.withFindings) },
        ].map((card) => (
          <div
            key={card.label}
            style={{
              border: "1px solid var(--app-border)",
              background:
                "color-mix(in srgb, var(--app-input-bg) 86%, transparent)",
              borderRadius: 8,
              padding: "10px 12px",
            }}
          >
            <div
              style={{
                ...mono,
                fontSize: 9,
                textTransform: "uppercase",
                color: "var(--app-muted)",
                marginBottom: 4,
              }}
            >
              {card.label}
            </div>
            <div style={{ ...mono, fontSize: 18, fontWeight: 700 }}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.6fr repeat(4, minmax(120px, 1fr))",
          gap: 8,
          marginBottom: 12,
        }}
      >
        <input
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          placeholder="Search package, version, license, component..."
          style={{
            ...mono,
            background: "var(--app-input-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            padding: "8px 10px",
            color: "var(--app-fg)",
            fontSize: 12,
          }}
        />
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          style={{
            ...mono,
            background: "var(--app-input-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            padding: "8px 10px",
            color: "var(--app-fg)",
            fontSize: 12,
          }}
        >
          <option value="all">All Risk</option>
          {RISK_ORDER.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <select
          value={licenseFilter}
          onChange={(e) => setLicenseFilter(e.target.value)}
          style={{
            ...mono,
            background: "var(--app-input-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            padding: "8px 10px",
            color: "var(--app-fg)",
            fontSize: 12,
          }}
        >
          <option value="all">All Licenses</option>
          {distinctLicenses.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
        <select
          value={componentFilter}
          onChange={(e) => setComponentFilter(e.target.value)}
          style={{
            ...mono,
            background: "var(--app-input-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            padding: "8px 10px",
            color: "var(--app-fg)",
            fontSize: 12,
          }}
        >
          <option value="all">All Components</option>
          {distinctComponents.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          value={findingsFilter}
          onChange={(e) =>
            setFindingsFilter(e.target.value as "all" | "with" | "without")
          }
          style={{
            ...mono,
            background: "var(--app-input-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            padding: "8px 10px",
            color: "var(--app-fg)",
            fontSize: 12,
          }}
        >
          <option value="all">All Findings</option>
          <option value="with">With Findings</option>
          <option value="without">No Findings</option>
        </select>
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        {(["package", "component", "license"] as const).map((m) => {
          const active = viewMode === m;
          return (
            <button
              key={m}
              type="button"
              onClick={() => setViewMode(m)}
              style={{
                ...mono,
                fontSize: 11,
                borderRadius: 20,
                padding: "6px 12px",
                border: active
                  ? "1px solid var(--app-accent)"
                  : "1px solid var(--app-border)",
                background: active
                  ? "color-mix(in srgb, var(--app-accent) 18%, transparent)"
                  : "var(--app-input-bg)",
                color: active ? "var(--app-accent)" : "var(--app-muted)",
                cursor: "pointer",
              }}
            >
              {m === "package"
                ? "By Package"
                : m === "component"
                  ? "By Component"
                  : "By License"}
            </button>
          );
        })}
      </div>

      {pasteOpen && (
        <div style={{ marginBottom: 20 }}>
          <textarea
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            placeholder='Paste CycloneDX JSON, e.g. {"components":[{"name":"pkg","version":"1.0","licenses":[{"license":{"id":"MIT"}}]}]}'
            style={{
              width: "100%",
              minHeight: 120,
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              padding: 12,
              color: "var(--app-fg)",
              fontSize: 12,
              fontFamily: "monospace",
              marginBottom: 8,
            }}
          />
          <button
            onClick={handlePaste}
            disabled={!pasteText.trim()}
            style={{
              ...mono,
              background: "var(--app-accent)",
              border: "none",
              borderRadius: 4,
              padding: "8px 16px",
              color: "#fff",
              fontSize: 12,
              cursor: pasteText.trim() ? "pointer" : "not-allowed",
            }}
          >
            Import
          </button>
        </div>
      )}

      <div
        style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}
      >
        {(["Critical", "High", "Medium", "Low"] as const).map((risk) => (
          <div
            key={risk}
            style={{
              ...mono,
              fontSize: 11,
              color:
                risk === "Critical"
                  ? "var(--app-danger)"
                  : risk === "High"
                    ? "var(--app-warning)"
                    : "var(--app-muted)",
            }}
          >
            {risk}: {(byRisk[risk] ?? []).length}
          </div>
        ))}
      </div>

      <div
        style={{
          border: "1px solid var(--app-border)",
          borderRadius: 6,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              viewMode === "package"
                ? "1fr 90px 120px 1fr 80px 70px"
                : "1fr 110px 90px 80px",
            gap: 12,
            padding: "10px 14px",
            background: "var(--app-header-bg)",
            ...mono,
            fontSize: 9,
            fontWeight: 700,
            color: "var(--app-muted)",
            textTransform: "uppercase",
          }}
        >
          {viewMode === "package" ? (
            <>
              <SortableHeader label="Package" colKey="name" />
              <SortableHeader label="Version" colKey="version" />
              <SortableHeader label="License" colKey="license" />
              <SortableHeader label="Component" colKey="component" />
              <SortableHeader label="Risk" colKey="risk" />
              <SortableHeader label="Findings" colKey="findings" />
            </>
          ) : (
            <>
              <span>{viewMode === "component" ? "Component" : "License"}</span>
              <span>Packages</span>
              <span>Risk</span>
              <span>Findings</span>
            </>
          )}
        </div>
        {viewMode === "package"
          ? sortedPackages.map((pkg, idx) => {
              const risk = getLicenseRisk(pkg);
              const findingCount = findingCountByComponent.get(pkg.id) ?? 0;
              return (
                <div
                  key={pkg.id}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 90px 120px 1fr 80px 70px",
                    gap: 12,
                    padding: "10px 14px",
                    borderTop: "1px solid var(--app-border)",
                    background:
                      idx % 2 === 0
                        ? "transparent"
                        : "color-mix(in srgb, var(--app-input-bg) 68%, transparent)",
                    ...mono,
                    fontSize: 12,
                    color: "var(--app-fg)",
                  }}
                >
                  <span>{pkg.name}</span>
                  <span style={{ color: "var(--app-muted)" }}>
                    {pkg.version}
                  </span>
                  <span>{pkg.license || "Unknown"}</span>
                  <span style={{ color: "var(--app-muted)" }}>
                    {pkg.component || "—"}
                  </span>
                  <span
                    style={{
                      color:
                        risk === "Critical"
                          ? "var(--app-danger)"
                          : risk === "High"
                            ? "var(--app-warning)"
                            : risk === "Medium"
                              ? "var(--app-accent)"
                              : "var(--app-success)",
                    }}
                  >
                    {risk}
                  </span>
                  <span
                    style={{
                      color:
                        findingCount > 0
                          ? "var(--app-danger)"
                          : "var(--app-muted)",
                    }}
                  >
                    {findingCount}
                  </span>
                </div>
              );
            })
          : groupedRows.map((row, idx) => {
              const risk =
                RISK_ORDER[row.worstRiskIndex] ??
                (row.worstRiskIndex === 99 ? "Unknown" : "Low");
              return (
                <div
                  key={row.key}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 110px 90px 80px",
                    gap: 12,
                    padding: "10px 14px",
                    borderTop: "1px solid var(--app-border)",
                    background:
                      idx % 2 === 0
                        ? "transparent"
                        : "color-mix(in srgb, var(--app-input-bg) 68%, transparent)",
                    ...mono,
                    fontSize: 12,
                    color: "var(--app-fg)",
                  }}
                >
                  <span>{row.key || "—"}</span>
                  <span style={{ color: "var(--app-muted)" }}>
                    {row.packages.length}
                  </span>
                  <span
                    style={{
                      color:
                        risk === "Critical"
                          ? "var(--app-danger)"
                          : risk === "High"
                            ? "var(--app-warning)"
                            : risk === "Medium"
                              ? "var(--app-accent)"
                              : "var(--app-success)",
                    }}
                  >
                    {risk}
                  </span>
                  <span
                    style={{
                      color:
                        row.findings > 0
                          ? "var(--app-danger)"
                          : "var(--app-muted)",
                    }}
                  >
                    {row.findings}
                  </span>
                </div>
              );
            })}
      </div>
    </div>
  );
}
