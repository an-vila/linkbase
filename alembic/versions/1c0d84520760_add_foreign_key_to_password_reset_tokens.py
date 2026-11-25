
"""add foreign key to password reset tokens

Revision ID: 1c0d84520760
Revises: 1d9b307fcb2d
"""

from typing import Sequence, Union

from alembic import op


revision: str = "1c0d84520760"
down_revision: Union[str, Sequence[str], None] = "1d9b307fcb2d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass

