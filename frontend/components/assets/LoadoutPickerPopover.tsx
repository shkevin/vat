"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useAuth } from "@/contexts/AuthContext";
import { useVATData } from "@/contexts/VATDataContext";
import { SearchInput } from "@/components/ui/SearchInput";
import { addLoadoutItems, createLoadout } from "@/lib/api";
import type { AssetLoadout } from "@/lib/assetLoadoutStorage";

interface LoadoutPickerPopoverProps {
  /** Anchor element bounds — popover positions just above. */
  anchorRect: DOMRect | null;
  selectedAssetIds: string[];
  onClose: () => void;
  /** Called after a successful add/create so the parent can clear selection. */
  onSaved: () => void;
}

const POPOVER_WIDTH = 320;
const POPOVER_MAX_HEIGHT = 360;

export function LoadoutPickerPopover({
  anchorRect,
  selectedAssetIds,
  onClose,
  onSaved,
}: LoadoutPickerPopoverProps) {
  const { token, user } = useAuth();
  const auth = useMemo(
    () => ({ token: token ?? undefined, userEmail: user?.email ?? undefined }),
    [token, user?.email],
  );
  const { loadouts, refetch } = useVATData();

  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [shareWithTeam, setShareWithTeam] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Auto-focus the search input on open so users can type immediately.
  useEffect(() => {
    searchInputRef.current?.focus();
  }, []);

  // Close on Esc.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Close on outside-click. Use mousedown so the click that opens the popover
  // (which fired its own mousedown on the trigger) doesn't immediately close it.
  useEffect(() => {
    const onMouseDown = (e: MouseEvent) => {
      if (!popoverRef.current) return;
      if (!popoverRef.current.contains(e.target as Node)) onClose();
    };
    // Defer one tick so the open click doesn't trigger close.
    const timer = setTimeout(
      () => document.addEventListener("mousedown", onMouseDown),
      0,
    );
    return () => {
      clearTimeout(timer);
      document.removeEventListener("mousedown", onMouseDown);
    };
  }, [onClose]);

  const filteredLoadouts = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return loadouts;
    return loadouts.filter((l) => l.name.toLowerCase().includes(q));
  }, [loadouts, search]);

  const handleAddToExisting = useCallback(
    async (loadout: AssetLoadout) => {
      setBusyId(loadout.id);
      setError(null);
      try {
        await addLoadoutItems(loadout.id, selectedAssetIds, auth);
        await refetch();
        onSaved();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to update loadout");
        setBusyId(null);
      }
    },
    [auth, refetch, selectedAssetIds, onSaved],
  );

  const handleCreate = useCallback(async () => {
    const name = newName.trim();
    if (!name) {
      setError("Name is required");
      return;
    }
    setBusyId("__new__");
    setError(null);
    try {
      await createLoadout(
        {
          name,
          asset_ids: selectedAssetIds,
          shared_with_team: shareWithTeam,
        },
        auth,
      );
      await refetch();
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create loadout");
      setBusyId(null);
    }
  }, [auth, newName, refetch, selectedAssetIds, shareWithTeam, onSaved]);

  if (!anchorRect) return null;

  // Position the popover above the anchor. Clamp to viewport so it doesn't
  // overflow horizontally. Bottom-aligned so the dock-bar trigger is the
  // visual anchor and the popover grows upward.
  const left = Math.min(
    Math.max(8, anchorRect.left),
    window.innerWidth - POPOVER_WIDTH - 8,
  );
  const bottom = Math.max(8, window.innerHeight - anchorRect.top + 8);

  return (
    <div
      ref={popoverRef}
      role="dialog"
      aria-label="Add to loadout"
      style={{
        position: "fixed",
        left,
        bottom,
        width: POPOVER_WIDTH,
        maxHeight: POPOVER_MAX_HEIGHT,
        background: "var(--ui-surface-1)",
        border: "1px solid var(--ui-border)",
        borderRadius: 8,
        boxShadow: "0 8px 24px rgba(0,0,0,0.18)",
        display: "flex",
        flexDirection: "column",
        zIndex: 1000,
      }}
    >
      <div
        style={{
          padding: "10px 12px",
          borderBottom: "1px solid var(--ui-border-subtle)",
          fontSize: 12,
          fontWeight: 600,
          color: "var(--ui-text-muted)",
        }}
      >
        Add {selectedAssetIds.length} asset
        {selectedAssetIds.length === 1 ? "" : "s"} to loadout
      </div>

      {!creating && (
        <SearchInput
          ref={searchInputRef}
          placeholder="Search loadouts…"
          value={search}
          onValueChange={setSearch}
          style={{
            margin: "8px 12px",
            padding: "6px 8px",
            border: "1px solid var(--ui-border)",
            borderRadius: 4,
            fontSize: 13,
            background: "var(--ui-surface-2)",
            color: "var(--ui-text-primary)",
          }}
        />
      )}

      <div
        style={{
          flex: 1,
          overflowY: "auto",
          minHeight: 0,
        }}
      >
        {!creating && filteredLoadouts.length === 0 && (
          <div
            style={{
              padding: 16,
              fontSize: 12,
              color: "var(--ui-text-muted)",
              textAlign: "center",
            }}
          >
            {search.trim() ? "No matches." : "No loadouts yet."}
          </div>
        )}
        {!creating &&
          filteredLoadouts.map((l) => {
            const busy = busyId === l.id;
            return (
              <button
                key={l.id}
                type="button"
                onClick={() => handleAddToExisting(l)}
                disabled={busy || busyId !== null}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "stretch",
                  width: "100%",
                  textAlign: "left",
                  padding: "8px 12px",
                  background: "transparent",
                  border: "none",
                  cursor: busy ? "wait" : "pointer",
                  borderBottom: "1px solid var(--ui-border-subtle)",
                  fontSize: 13,
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background =
                    "color-mix(in srgb, var(--ui-surface-2) 70%, transparent)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "transparent";
                }}
              >
                <span
                  style={{ fontWeight: 600, color: "var(--ui-text-primary)" }}
                >
                  {l.name}
                </span>
                <span style={{ fontSize: 11, color: "var(--ui-text-muted)" }}>
                  {l.assetIds.length} asset
                  {l.assetIds.length === 1 ? "" : "s"}
                  {busy && " · adding…"}
                </span>
              </button>
            );
          })}
      </div>

      {creating ? (
        <div
          style={{
            padding: 12,
            borderTop: "1px solid var(--ui-border-subtle)",
            display: "flex",
            flexDirection: "column",
            gap: 8,
          }}
        >
          <input
            type="text"
            placeholder="Loadout name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            disabled={busyId !== null}
            autoFocus
            style={{
              padding: "6px 8px",
              border: "1px solid var(--ui-border)",
              borderRadius: 4,
              fontSize: 13,
              background: "var(--ui-surface-2)",
              color: "var(--ui-text-primary)",
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCreate();
            }}
          />
          <label
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              fontSize: 12,
            }}
          >
            <input
              type="checkbox"
              checked={shareWithTeam}
              onChange={(e) => setShareWithTeam(e.target.checked)}
              disabled={busyId !== null}
            />
            Share with team
          </label>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              onClick={handleCreate}
              disabled={busyId !== null || !newName.trim()}
              style={{
                flex: 1,
                padding: "6px 12px",
                borderRadius: 4,
                background:
                  "color-mix(in srgb, var(--ui-accent) 24%, transparent)",
                color: "var(--ui-accent)",
                border:
                  "1px solid color-mix(in srgb, var(--ui-accent) 45%, transparent)",
                fontSize: 13,
                fontWeight: 600,
                cursor:
                  busyId !== null || !newName.trim() ? "not-allowed" : "pointer",
                opacity: busyId !== null || !newName.trim() ? 0.5 : 1,
              }}
            >
              {busyId === "__new__" ? "Creating…" : "Create"}
            </button>
            <button
              type="button"
              onClick={() => {
                setCreating(false);
                setNewName("");
                setShareWithTeam(false);
                setError(null);
              }}
              disabled={busyId !== null}
              style={{
                padding: "6px 12px",
                border: "1px solid var(--ui-border)",
                borderRadius: 4,
                background: "transparent",
                color: "var(--ui-text-secondary)",
                fontSize: 13,
                cursor: "pointer",
              }}
            >
              Back
            </button>
          </div>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setCreating(true)}
          style={{
            padding: "10px 12px",
            borderTop: "1px solid var(--ui-border-subtle)",
            background: "transparent",
            border: "none",
            cursor: "pointer",
            textAlign: "left",
            fontSize: 13,
            color: "var(--ui-accent)",
            fontWeight: 600,
          }}
        >
          + New loadout
        </button>
      )}

      {error && (
        <div
          style={{
            padding: "6px 12px",
            fontSize: 12,
            color: "var(--ui-danger)",
            borderTop: "1px solid var(--ui-border-subtle)",
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
}
