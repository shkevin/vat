#!/usr/bin/env bash
# Runs on the HOST before the container starts.
# Captures the current GH token so the container doesn't need 'gh auth login'.
set -euo pipefail

ENV_FILE="$(dirname "$0")/.env.devcontainer"

if command -v gh &>/dev/null && gh auth status &>/dev/null 2>&1; then
  TOKEN="$(gh auth token 2>/dev/null || true)"
  if [[ -n "${TOKEN}" ]]; then
    echo "GH_TOKEN=${TOKEN}" > "${ENV_FILE}"
    echo "[init] GH token written to .devcontainer/.env.devcontainer"
  else
    echo "[init] gh is installed but returned no token — skipping GH_TOKEN"
    touch "${ENV_FILE}"
  fi
else
  echo "[init] gh CLI not found or not authenticated on host — skipping GH_TOKEN"
  touch "${ENV_FILE}"
fi

# SSH: ~/.ssh is bind-mounted into the container (see devcontainer.json mounts).
