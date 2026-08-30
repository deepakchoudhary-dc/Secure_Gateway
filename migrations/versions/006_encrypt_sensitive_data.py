"""Encrypt existing sensitive application data.

Revision ID: 006_encrypt_sensitive_data
Revises: 005_idempotency_and_revocations
"""
from alembic import op
import sqlalchemy as sa

from src.secrets.field_crypto import encrypt_field, is_encrypted


revision = "006_encrypt_sensitive_data"
down_revision = "005_idempotency_and_revocations"
branch_labels = None
depends_on = None


def _encrypt_columns(table_name, columns):
    bind = op.get_bind()
    table = sa.table(
        table_name,
        sa.column("id", sa.Integer()),
        *(sa.column(column, sa.Text()) for column in columns),
    )
    for row in bind.execute(sa.select(table)).mappings():
        encrypted = {
            column: encrypt_field(row[column])
            for column in columns
            if row[column] is not None and not is_encrypted(row[column])
        }
        if encrypted:
            bind.execute(table.update().where(table.c.id == row["id"]).values(**encrypted))


def upgrade():
    _encrypt_columns(
        "security_logs",
        ["prompt", "system_prompt", "retrieved_context", "response", "anomalies", "trace_json"],
    )
    _encrypt_columns(
        "hitl_requests",
        ["prompt", "system_prompt", "retrieved_context", "context", "callback_url"],
    )
    _encrypt_columns("outbox_events", ["payload_json"])
    _encrypt_columns("policy_configs", ["rules_json"])
    _encrypt_columns("detection_feedback", ["prompt"])


def downgrade():
    # Encryption is intentionally not reversed during schema rollback.
    pass
