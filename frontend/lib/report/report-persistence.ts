/**
 * Persistence layer for report definitions.
 * Uses localStorage for VAT (API backend can be added later).
 */

import type { ReportDefinition } from "./report-types";
import { normalizeReportDefinitionLayout } from "./report-types";

export interface SavedReportMeta {
  id: string;
  name: string;
  updatedAt: string;
}

export interface ReportDefinitionPersistence {
  list(): Promise<SavedReportMeta[]>;
  load(id: string): Promise<ReportDefinition | null>;
  save(
    id: string | null,
    name: string,
    definition: ReportDefinition,
  ): Promise<string>;
  delete(id: string): Promise<void>;
}

const STORAGE_KEY = "vat:report-definitions";

interface StoredReport {
  id: string;
  name: string;
  updatedAt: string;
  definition: ReportDefinition;
}

function readStored(): StoredReport[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (r): r is StoredReport =>
        r &&
        typeof r === "object" &&
        typeof (r as StoredReport).id === "string" &&
        typeof (r as StoredReport).name === "string" &&
        typeof (r as StoredReport).updatedAt === "string" &&
        typeof (r as StoredReport).definition === "object",
    );
  } catch {
    return [];
  }
}

function writeStored(reports: StoredReport[]): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(reports));
  } catch {
    // ignore
  }
}

export function createLocalStoragePersistence(): ReportDefinitionPersistence {
  return {
    async list(): Promise<SavedReportMeta[]> {
      const reports = readStored();
      return reports
        .sort(
          (a, b) =>
            new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(),
        )
        .map((r) => ({ id: r.id, name: r.name, updatedAt: r.updatedAt }));
    },
    async load(id: string): Promise<ReportDefinition | null> {
      const reports = readStored();
      const found = reports.find((r) => r.id === id);
      if (!found) return null;
      const def = normalizeReportDefinitionLayout(
        JSON.parse(JSON.stringify(found.definition)),
      );
      return def;
    },
    async save(
      id: string | null,
      name: string,
      definition: ReportDefinition,
    ): Promise<string> {
      const reports = readStored();
      const now = new Date().toISOString();
      const normalized = normalizeReportDefinitionLayout(
        JSON.parse(JSON.stringify(definition)),
      );
      if (id) {
        const idx = reports.findIndex((r) => r.id === id);
        if (idx >= 0) {
          reports[idx] = {
            id,
            name: name.trim() || "Untitled report",
            updatedAt: now,
            definition: normalized,
          };
          writeStored(reports);
          return id;
        }
      }
      const newId = `report-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 9)}`;
      reports.push({
        id: newId,
        name: name.trim() || "Untitled report",
        updatedAt: now,
        definition: normalized,
      });
      writeStored(reports);
      return newId;
    },
    async delete(id: string): Promise<void> {
      const reports = readStored().filter((r) => r.id !== id);
      writeStored(reports);
    },
  };
}

let defaultPersistence: ReportDefinitionPersistence | null = null;

export function getReportPersistence(): ReportDefinitionPersistence {
  if (!defaultPersistence) {
    defaultPersistence = createLocalStoragePersistence();
  }
  return defaultPersistence;
}

export function setReportPersistence(impl: ReportDefinitionPersistence): void {
  defaultPersistence = impl;
}
