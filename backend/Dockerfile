FROM python:3.11-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-dev

# Copy application code
COPY . .

# Default runtime command.
# - VAT_RUN_MIGRATIONS=true: migrate then start API (single-container mode)
# - VAT_RUN_MIGRATIONS=false: start API only (recommended with dedicated migrate job)
CMD ["sh", "-c", "if [ \"${VAT_RUN_MIGRATIONS:-false}\" = \"true\" ]; then uv run alembic upgrade head; fi; uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${VAT_UVICORN_WORKERS:-2}"]
