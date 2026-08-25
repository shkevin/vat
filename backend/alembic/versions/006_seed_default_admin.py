"""seed default admin user

Revision ID: 006
Revises: 005
Create Date: 2026-02-24

The admin password comes from VAT_ADMIN_BOOTSTRAP_PASSWORD when set; otherwise a
random one is generated and logged once. It is never reset on re-run — an
operator who rotates the password keeps it.

"""

import logging
import os
import secrets
from typing import Sequence, Union

import bcrypt
from alembic import op
from sqlalchemy import text

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

log = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        text(
            "INSERT INTO tenants (id, name, created_at) VALUES ('t-default', 'Default Org', NOW()) "
            "ON CONFLICT (id) DO NOTHING"
        )
    )

    password = os.environ.get("VAT_ADMIN_BOOTSTRAP_PASSWORD")
    generated = password is None
    if generated:
        password = secrets.token_urlsafe(18)
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # DO NOTHING, not DO UPDATE: re-running a migration must never clobber a
    # password the operator has since rotated.
    result = conn.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', :pw_hash, NOW()) "
            "ON CONFLICT (id) DO NOTHING"
        ),
        {"pw_hash": pw_hash},
    )

    if result.rowcount and generated:
        log.warning(
            "\n"
            "================================================================\n"
            "  VAT bootstrap admin created\n"
            "    username: admin   (or admin@vat.local)\n"
            "    password: %s\n"
            "  Save this now — it is not stored anywhere else and will not be\n"
            "  shown again. Set VAT_ADMIN_BOOTSTRAP_PASSWORD to choose your own.\n"
            "================================================================",
            password,
        )


def downgrade() -> None:
    op.execute("DELETE FROM users WHERE id = 'admin'")
