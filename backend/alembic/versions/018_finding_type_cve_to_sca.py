"""Rename finding_type CVE → SCA (CVE is an identifier, not a classifier)

Revision ID: 018
Revises: 017
Create Date: 2026-03-02

"""

from typing import Sequence, Union

from alembic import op

revision: str = "018"
down_revision: Union[str, None] = "017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PostgreSQL: cannot remove enum value directly. Create new type, migrate, drop old.
    op.execute("CREATE TYPE findingtype_new AS ENUM ('SCA', 'Secret', 'IaC', 'SAST', 'License')")
    op.execute("ALTER TABLE findings ADD COLUMN finding_type_new findingtype_new")
    op.execute(
        "UPDATE findings SET finding_type_new = CASE "
        "WHEN finding_type::text = 'CVE' THEN 'SCA'::findingtype_new "
        "ELSE finding_type::text::findingtype_new END"
    )
    op.execute("ALTER TABLE findings DROP COLUMN finding_type")
    op.execute("ALTER TABLE findings RENAME COLUMN finding_type_new TO finding_type")
    op.execute("ALTER TABLE findings ALTER COLUMN finding_type SET NOT NULL")
    op.execute("DROP TYPE findingtype")
    op.execute("ALTER TYPE findingtype_new RENAME TO findingtype")


def downgrade() -> None:
    op.execute("CREATE TYPE findingtype_old AS ENUM ('CVE', 'Secret', 'IaC', 'SAST', 'License')")
    op.execute("ALTER TABLE findings ADD COLUMN finding_type_old findingtype_old")
    op.execute(
        "UPDATE findings SET finding_type_old = CASE "
        "WHEN finding_type::text = 'SCA' THEN 'CVE'::findingtype_old "
        "ELSE finding_type::text::findingtype_old END"
    )
    op.execute("ALTER TABLE findings DROP COLUMN finding_type")
    op.execute("ALTER TABLE findings RENAME COLUMN finding_type_old TO finding_type")
    op.execute("ALTER TABLE findings ALTER COLUMN finding_type SET NOT NULL")
    op.execute("DROP TYPE findingtype")
    op.execute("ALTER TYPE findingtype_old RENAME TO findingtype")
