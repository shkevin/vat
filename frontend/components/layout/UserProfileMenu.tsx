"use client";

import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { UserPreferencesPane } from "@/components/layout/UserPreferencesPane";
import type { UserPreferences } from "@/lib/userSettings";

/** White user silhouette icon matching the reference design — head + shoulders */
function UserProfileIcon({ size = 32 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <circle cx="16" cy="16" r="16" fill="var(--app-input-bg, #0d1f2d)" />
      <circle cx="16" cy="11" r="4" fill="white" />
      <path d="M8 28c0-4.4 3.6-8 8-8s8 3.6 8 8" fill="white" />
    </svg>
  );
}

interface UserProfileMenuProps {
  onPreferencesChange?: (prefs: UserPreferences) => void;
  onViewChange?: (id: string) => void;
}

export function UserProfileMenu({
  onPreferencesChange,
  onViewChange,
}: UserProfileMenuProps) {
  const { user } = useAuth();
  const [paneOpen, setPaneOpen] = useState(false);

  if (!user) return null;

  return (
    <>
      <button
        type="button"
        onClick={() => setPaneOpen(true)}
        title={`Signed in as ${user.email}`}
        aria-label="User profile and preferences"
        aria-expanded={paneOpen}
        aria-haspopup="dialog"
        style={{
          background: "var(--app-input-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: "50%",
          padding: 4,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: 40,
          height: 40,
        }}
      >
        <UserProfileIcon size={24} />
      </button>

      <UserPreferencesPane
        open={paneOpen}
        onClose={() => setPaneOpen(false)}
        onPreferencesChange={onPreferencesChange}
        onNavigateToReport={
          onViewChange ? () => onViewChange("report") : undefined
        }
        onNavigateToFindings={
          onViewChange ? () => onViewChange("findings") : undefined
        }
      />
    </>
  );
}
