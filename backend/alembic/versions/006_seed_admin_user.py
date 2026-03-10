"""seed default admin user (admin/admin)

Revision ID: 006
Revises: 005
Create Date: 2026-02-24

"""

from typing import Sequence, Union

import bcrypt
from alembic import op
from sqlalchemy import text

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        text(
            "INSERT INTO tenants (id, name, created_at) VALUES ('t-default', 'Default Org', NOW()) "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
    conn.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', :pw_hash, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET "
            "password_hash = EXCLUDED.password_hash, email = EXCLUDED.email, "
            "role = EXCLUDED.role, tenant_id = EXCLUDED.tenant_id"
        ),
        {"pw_hash": pw_hash},
    )


def downgrade() -> None:
    op.execute("DELETE FROM users WHERE id = 'admin'")
