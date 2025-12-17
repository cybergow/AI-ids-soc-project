"""Add ml_models

Revision ID: c3d4e5f6a7b8
Revises: b1c2d3e4f5a6
Create Date: 2025-12-16 12:45:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b1c2d3e4f5a6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ml_models",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("version", sa.String(length=20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("model_type", sa.Enum("CLASSIFICATION", "ANOMALY_DETECTION", "REGRESSION", "CLUSTERING", name="modeltype"), nullable=False),
        sa.Column("status", sa.Enum("TRAINING", "READY", "FAILED", "DEPRECATED", name="modelstatus"), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_ml_models_id"), "ml_models", ["id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_ml_models_id"), table_name="ml_models")
    op.drop_table("ml_models")
