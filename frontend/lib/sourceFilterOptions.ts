import { displaySourceName } from "@/lib/utils";

type FindingSource = {
  source?: string | null;
};

type ConfiguredSource = {
  id?: string | null;
  name?: string | null;
};

export type SourceFilterOption = {
  value: string;
  label: string;
};

function sourceFilterLabel(value: string | null | undefined): string {
  const display = displaySourceName(value) || value?.trim() || "";
  const folderScanMatch = display.match(/^folder scan\s*\((.+)\)$/i);
  if (!folderScanMatch) return display;
  return displaySourceName(folderScanMatch[1]) || folderScanMatch[1].trim();
}

export function sourceFilterKey(
  sourceIdOrName: string | null | undefined,
  configuredName?: string | null,
): string {
  return sourceFilterLabel(configuredName ?? sourceIdOrName).toLowerCase();
}

export function buildSourceFilterOptions(
  findings: FindingSource[],
  sources: ConfiguredSource[],
): SourceFilterOption[] {
  const configuredNames = new Map(
    sources
      .filter((source) => source.id)
      .map((source) => [source.id as string, source.name ?? source.id]),
  );
  const options = new Map<string, { label: string; count: number }>();

  const ensureOption = (key: string, label: string) => {
    if (!key) return;
    if (!options.has(key)) {
      options.set(key, { label, count: 0 });
    }
  };

  for (const source of sources) {
    const key = sourceFilterKey(source.id, source.name);
    ensureOption(key, sourceFilterLabel(source.name ?? source.id));
  }

  for (const finding of findings) {
    if (!finding.source) continue;
    const configuredName = configuredNames.get(finding.source);
    const key = sourceFilterKey(finding.source, configuredName);
    const label = sourceFilterLabel(configuredName ?? finding.source);
    ensureOption(key, label);
    const option = options.get(key);
    if (option) option.count += 1;
  }

  return [...options.entries()]
    .map(([value, option]) => ({
      value,
      label: `${option.label} (${option.count})`,
    }))
    .sort((a, b) => a.label.localeCompare(b.label));
}
