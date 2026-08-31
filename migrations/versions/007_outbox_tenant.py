"""Outbox tenant_id for erasure

Revision ID: 007_outbox_tenant
Revises: 006_encrypt_sensitive_data
"""
from alembic import op
import sqlalchemy as sa

revision = "007_outbox_tenant"
down_revision = "006_encrypt_sensitive_data"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("outbox_events", sa.Column("tenant_id", sa.String(100), nullable=True))
    op.create_index("ix_outbox_events_tenant_id", "outbox_events", ["tenant_id"])


def downgrade():
    op.drop_index("ix_outbox_events_tenant_id", table_name="outbox_events")
    op.drop_column("outbox_events", "tenant_id")
