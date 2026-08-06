"""Add expires_at column to offline_tokens.

Offline tokens were stored without any lifetime, so a token issued once stayed
valid in the database indefinitely. This column carries the application-level
expiry the store now enforces on read.

Revision ID: 127
Revises: 126
Create Date: 2026-08-05
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '127'
down_revision: str | None = '126'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable so existing rows migrate without a backfill; the store treats a
    # NULL expires_at as "legacy token, expire it on next read" rather than as
    # "never expires", so pre-existing tokens do not stay immortal.
    op.add_column(
        'offline_tokens',
        sa.Column('expires_at', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('offline_tokens', 'expires_at')
