#!/usr/bin/env bash
# Runs inside the devcontainer after creation.
# Idempotent — safe to re-run on container rebuild.
set -euo pipefail

WORKSPACE="/workspaces/vat"

# ── Docker-outside-of-Docker bind mount fix ──────────────────────────────────
# The devcontainer uses docker-outside-of-docker, so the Docker daemon runs on
# the host. Bind mount paths in docker-compose.yml must resolve on the *host*,
# not inside the container. Detect the host path from mountinfo and export it
# so docker-compose.yml can use ${HOST_PROJECT_PATH:-.} for all bind mounts.
echo "==> [0/4] Detecting host project path for Docker bind mounts..."
HOST_PATH=""
if [[ -f /proc/self/mountinfo ]]; then
  HOST_PATH="$(awk -v mnt="${WORKSPACE}" '$5 == mnt {print $4}' /proc/self/mountinfo | head -1)"
fi
if [[ -n "${HOST_PATH}" ]]; then
  # Write to .env so docker compose picks it up automatically
  if grep -q '^HOST_PROJECT_PATH=' "${WORKSPACE}/.env" 2>/dev/null; then
    sed -i "s|^HOST_PROJECT_PATH=.*|HOST_PROJECT_PATH=${HOST_PATH}|" "${WORKSPACE}/.env"
  else
    echo "" >> "${WORKSPACE}/.env"
    echo "HOST_PROJECT_PATH=${HOST_PATH}" >> "${WORKSPACE}/.env"
  fi
  echo "    HOST_PROJECT_PATH=${HOST_PATH} written to .env"
else
  echo "    WARNING: Could not detect host path — Docker bind mounts may not work."
  echo "    Set HOST_PROJECT_PATH manually in .env (e.g., HOST_PROJECT_PATH=/home/user/code/vat)"
fi
# Ensure VAT_FRONTEND_SKIP_BUILD is defined to suppress Compose warnings
if ! grep -q '^VAT_FRONTEND_SKIP_BUILD=' "${WORKSPACE}/.env" 2>/dev/null; then
  echo "VAT_FRONTEND_SKIP_BUILD=" >> "${WORKSPACE}/.env"
fi

echo "==> [1/4] Installing backend Python dependencies..."
if [[ -f "${WORKSPACE}/backend/pyproject.toml" ]]; then
  (cd "${WORKSPACE}/backend" && uv sync --frozen)
  echo "    Backend deps installed via uv."
else
  echo "    WARNING: backend/pyproject.toml not found, skipping."
fi

echo "==> [2/4] Downloading spaCy language model..."
if (cd "${WORKSPACE}/backend" && uv run python -c "import en_core_web_sm" 2>/dev/null); then
  echo "    en_core_web_sm already installed, skipping."
else
  (cd "${WORKSPACE}/backend" && uv run python -m spacy download en_core_web_sm) || \
    echo "    WARNING: spaCy model download failed (may need network access)."
fi

echo "==> [3/4] Installing frontend Node.js dependencies..."
if [[ -f "${WORKSPACE}/frontend/package.json" ]]; then
  (cd "${WORKSPACE}/frontend" && npm install)
  echo "    Frontend deps installed via npm."
else
  echo "    WARNING: frontend/package.json not found, skipping."
fi

echo "==> [4/4] Installing git hook to block --no-verify..."
GIT_WRAPPER='
# Block git commit --no-verify (set by post-create.sh)
git() {
  if [[ "$1" == "commit" ]]; then
    for arg in "$@"; do
      if [[ "$arg" == "--no-verify" || "$arg" == "-n" ]]; then
        echo "ERROR: --no-verify bypasses quality checks and is not allowed in this repo." >&2
        echo "Fix the pre-commit issue instead of skipping it." >&2
        return 1
      fi
    done
  fi
  command git "$@"
}
'
for RC in "${HOME}/.bashrc" "${HOME}/.zshrc"; do
  if [[ -f "${RC}" ]] && ! grep -q "Block git commit --no-verify" "${RC}"; then
    echo "${GIT_WRAPPER}" >> "${RC}"
  fi
done
echo "    git --no-verify guard installed."

echo ""
echo "Dev container ready."
echo ""
echo "Quick start:"
echo "  Backend:  cd backend && uv run uvicorn app.main:app --reload"
echo "  Frontend: cd frontend && npm run dev"
echo "  Full stack: docker compose up (from repo root)"
echo ""
echo "Run 'claude' to start Claude Code."
