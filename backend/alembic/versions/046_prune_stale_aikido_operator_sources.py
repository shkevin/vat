"""Prune stale Aikido source labels from operator findings.

Revision ID: 046
Revises: 045
Create Date: 2026-06-26

Operator/local-scanner findings could inherit an older Aikido source entry when
they deduplicated into an existing row. Source attribution is data, not a UI
concern, so normalize those rows once: when a finding has both Aikido and a
non-Aikido source in its source history, keep the scanner source history and
promote the first scanner source to primary if primary source is still Aikido.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "046"
down_revision: Union[str, None] = "045"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            WITH source_rows AS (
                SELECT
                    f.id,
                    f.source,
                    (
                        SELECT jsonb_agg(source_entry.elem ORDER BY source_entry.ord)
                        FROM jsonb_array_elements(COALESCE(f.sources, '[]'::jsonb))
                            WITH ORDINALITY AS source_entry(elem, ord)
                        WHERE lower(trim(source_entry.elem ->> 'name')) <> 'aikido'
                    ) AS scanner_sources,
                    (
                        SELECT source_entry.elem ->> 'name'
                        FROM jsonb_array_elements(COALESCE(f.sources, '[]'::jsonb))
                            WITH ORDINALITY AS source_entry(elem, ord)
                        WHERE lower(trim(source_entry.elem ->> 'name')) <> 'aikido'
                        ORDER BY source_entry.ord
                        LIMIT 1
                    ) AS first_scanner_source
                FROM findings f
                WHERE jsonb_typeof(COALESCE(f.sources, '[]'::jsonb)) = 'array'
                  AND EXISTS (
                      SELECT 1
                      FROM jsonb_array_elements(COALESCE(f.sources, '[]'::jsonb)) AS source_entry(elem)
                      WHERE lower(trim(source_entry.elem ->> 'name')) = 'aikido'
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM jsonb_array_elements(COALESCE(f.sources, '[]'::jsonb)) AS source_entry(elem)
                      WHERE lower(trim(source_entry.elem ->> 'name')) <> 'aikido'
                  )
            )
            UPDATE findings AS f
            SET
                source = CASE
                    WHEN lower(trim(COALESCE(f.source, ''))) = 'aikido'
                        THEN source_rows.first_scanner_source
                    ELSE f.source
                END,
                sources = COALESCE(source_rows.scanner_sources, '[]'::jsonb)
            FROM source_rows
            WHERE f.id = source_rows.id
              AND source_rows.first_scanner_source IS NOT NULL
            """
        )
    )


def downgrade() -> None:
    # No-op: removed stale Aikido source-history entries cannot be reconstructed.
    pass
