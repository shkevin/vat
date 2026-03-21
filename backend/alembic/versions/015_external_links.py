"""Replace tracker_id and source_issue_ids with external_links

Revision ID: 015
Revises: 014
Create Date: 2026-02-28

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "015"
down_revision: Union[str, None] = "014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add external_links column
    op.add_column(
        "findings",
        sa.Column(
            "external_links",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )

    # Backfill: migrate tracker_id and source_issue_ids into external_links
    op.execute("""
        DO $$
        DECLARE
            r RECORD;
            links jsonb := '[]'::jsonb;
            tracker_key text;
            source_key text;
            source_val text;
        BEGIN
            SELECT COALESCE(
                (SELECT value::jsonb->>'adapter' FROM settings WHERE key = 'tracker' LIMIT 1),
                'linear'
            ) INTO tracker_key;

            FOR r IN SELECT id, tracker_id, source_issue_ids FROM findings
            LOOP
                links := '[]'::jsonb;

                IF r.tracker_id IS NOT NULL AND r.tracker_id != '' THEN
                    links := links || jsonb_build_array(jsonb_build_object(
                        'adapter_key', COALESCE(tracker_key, 'linear'),
                        'kind', 'tracker',
                        'issue_id', r.tracker_id,
                        'created_at', to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                    ));
                END IF;

                IF r.source_issue_ids IS NOT NULL AND jsonb_typeof(r.source_issue_ids) = 'object' THEN
                    FOR source_key, source_val IN SELECT * FROM jsonb_each_text(r.source_issue_ids)
                    LOOP
                        links := links || jsonb_build_array(jsonb_build_object(
                            'adapter_key', source_key,
                            'kind', 'source',
                            'issue_id', source_val,
                            'created_at', to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                        ));
                    END LOOP;
                END IF;

                IF links != '[]'::jsonb THEN
                    UPDATE findings SET external_links = links WHERE id = r.id;
                END IF;
            END LOOP;
        END $$;
    """)

    # Drop old columns
    op.drop_column("findings", "tracker_id")
    op.drop_column("findings", "source_issue_ids")

    # GIN index for lookup
    op.execute(
        "CREATE INDEX idx_findings_external_links_gin ON findings USING GIN (external_links jsonb_path_ops)"
    )


def downgrade() -> None:
    op.drop_index("idx_findings_external_links_gin", table_name="findings")
    op.add_column(
        "findings",
        sa.Column("tracker_id", sa.String(64), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "source_issue_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
    )

    # Extract tracker_id and source_issue_ids from external_links (first tracker wins)
    op.execute("""
        DO $$
        DECLARE
            r RECORD;
            link jsonb;
            tid text;
            sids jsonb;
        BEGIN
            FOR r IN SELECT id, external_links FROM findings
            LOOP
                tid := NULL;
                sids := '{}'::jsonb;
                IF r.external_links IS NOT NULL AND jsonb_array_length(r.external_links) > 0 THEN
                    FOR link IN SELECT * FROM jsonb_array_elements(r.external_links)
                    LOOP
                        IF (link->>'kind') = 'tracker' AND tid IS NULL THEN
                            tid := link->>'issue_id';
                        ELSIF (link->>'kind') = 'source' THEN
                            sids := sids || jsonb_build_object(link->>'adapter_key', link->>'issue_id');
                        END IF;
                    END LOOP;
                END IF;
                UPDATE findings SET tracker_id = tid, source_issue_ids = CASE WHEN sids = '{}'::jsonb THEN NULL ELSE sids END WHERE id = r.id;
            END LOOP;
        END $$;
    """)

    op.drop_column("findings", "external_links")
