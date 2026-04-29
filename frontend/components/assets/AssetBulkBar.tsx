"use client";

import { useState } from "react";
import { Btn } from "@/components/atoms";
import { useAuth } from "@/contexts/AuthContext";
import { bulkDeleteAssets, addLoadoutItems, createLoadout } from "@/lib/api";
import { useVATData } from "@/contexts/VATDataContext";

interface AssetBulkBarProps {
  count: number;
  selectedAssetIds: string[];
  onDeselect: () => void;
  /** Trigger a refetch in the parent so deletions/loadout changes show up. */
  onMutated?: () => void;
}

type Mode = "idle" | "loadout" | "delete";

export function AssetBulkBar({
  count,
  selectedAssetIds,
  onDeselect,
  onMutated,
}: AssetBulkBarProps) {
  const { token, user, isAdmin } = useAuth();
  const auth = { token: token ?? undefined, userEmail: user?.email ?? undefined };
  const { loadouts, applyLoadout } = useVATData();
  const [mode, setMode] = useState<Mode>("idle");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pickedLoadoutId, setPickedLoadoutId] = useState<string>("__new__");
  const [newLoadoutName, setNewLoadoutName] = useState("");
  const [shareWithTeam, setShareWithTeam] = useState(false);

  const reset = () => {
    setMode("idle");
    setBusy(false);
    setErr(null);
    setPickedLoadoutId("__new__");
    setNewLoadoutName("");
    setShareWithTeam(false);
  };

  const handleAddToLoadout = async () => {
    setBusy(true);
    setErr(null);
    try {
      if (pickedLoadoutId === "__new__") {
        const name = newLoadoutName.trim();
        if (!name) {
          setErr("Name required");
          setBusy(false);
          return;
        }
        await createLoadout(
          {
            name,
            asset_ids: selectedAssetIds,
            shared_with_team: shareWithTeam,
          },
          auth,
        );
      } else {
        await addLoadoutItems(pickedLoadoutId, selectedAssetIds, auth);
      }
      reset();
      onDeselect();
      onMutated?.();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to update loadout");
      setBusy(false);
    }
  };

  const handleBulkDelete = async () => {
    setBusy(true);
    setErr(null);
    try {
      const result = await bulkDeleteAssets(selectedAssetIds, auth);
      const failed = result.failed + result.not_found;
      if (failed > 0) {
        setErr(
          `Deleted ${result.deleted}/${result.requested}. ${failed} skipped (see console).`,
        );
        // eslint-disable-next-line no-console
        console.warn("bulk-delete partial:", result);
      }
      reset();
      onDeselect();
      onMutated?.();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Bulk delete failed");
      setBusy(false);
    }
  };

  if (count === 0) return null;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.75rem",
        padding: "0.5rem 0.75rem",
        background: "var(--app-surface, #f5f5f5)",
        borderRadius: 6,
        border: "1px solid var(--app-border, #ddd)",
        flexWrap: "wrap",
      }}
      role="region"
      aria-label="Bulk asset actions"
    >
      <span style={{ fontWeight: 600 }}>
        {count} asset{count === 1 ? "" : "s"} selected
      </span>

      {mode === "idle" && (
        <>
          <Btn onClick={() => setMode("loadout")}>Add to loadout…</Btn>
          {isAdmin && (
            <Btn onClick={() => setMode("delete")} variant="danger">
              Delete…
            </Btn>
          )}
          <Btn onClick={onDeselect} variant="ghost">
            Deselect
          </Btn>
        </>
      )}

      {mode === "loadout" && (
        <>
          <label
            style={{ display: "inline-flex", gap: 6, alignItems: "center" }}
          >
            <span style={{ fontSize: 12 }}>Loadout</span>
            <select
              value={pickedLoadoutId}
              onChange={(e) => setPickedLoadoutId(e.target.value)}
              disabled={busy}
            >
              <option value="__new__">+ New loadout…</option>
              {loadouts.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </label>
          {pickedLoadoutId === "__new__" && (
            <>
              <label
                style={{ display: "inline-flex", gap: 6, alignItems: "center" }}
              >
                <span style={{ fontSize: 12 }}>Name</span>
                <input
                  type="text"
                  value={newLoadoutName}
                  onChange={(e) => setNewLoadoutName(e.target.value)}
                  placeholder="e.g. Kamiwaza v0.12.0 deliverables"
                  disabled={busy}
                  style={{ minWidth: 240 }}
                />
              </label>
              <label
                style={{
                  display: "inline-flex",
                  gap: "0.4rem",
                  alignItems: "center",
                }}
              >
                <input
                  type="checkbox"
                  checked={shareWithTeam}
                  onChange={(e) => setShareWithTeam(e.target.checked)}
                  disabled={busy}
                />
                Share with team
              </label>
            </>
          )}
          <Btn onClick={handleAddToLoadout} disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </Btn>
          <Btn onClick={reset} variant="ghost" disabled={busy}>
            Cancel
          </Btn>
        </>
      )}

      {mode === "delete" && (
        <>
          <span>Delete {count} asset(s) and all their findings?</span>
          <Btn onClick={handleBulkDelete} disabled={busy} variant="danger">
            {busy ? "Deleting…" : "Confirm delete"}
          </Btn>
          <Btn onClick={reset} variant="ghost" disabled={busy}>
            Cancel
          </Btn>
        </>
      )}

      {err && (
        <span style={{ color: "var(--app-error, #b00020)", fontSize: 12 }}>
          {err}
        </span>
      )}
      {/* applyLoadout retained import to avoid unused-import warnings if used later */}
      <span hidden>{Boolean(applyLoadout)}</span>
    </div>
  );
}
