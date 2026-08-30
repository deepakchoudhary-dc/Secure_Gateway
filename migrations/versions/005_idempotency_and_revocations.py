"""Add durable idempotency and JWT revocation state.

Revision ID: 005_idempotency_and_revocations
Revises: 004_hitl_priority_sla
"""
from alembic import op
import sqlalchemy as sa


revision = "005_idempotency_and_revocations"
down_revision = "004_hitl_priority_sla"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "idempotency_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(100), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("endpoint", sa.String(255), nullable=False),
        sa.Column("key_digest", sa.String(64), nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("state", sa.String(50), nullable=False),
        sa.Column("execution_token", sa.String(64), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("response_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("tenant_id", "subject", "endpoint", "key_digest", name="uq_idempotency_key"),
    )
    op.create_index("ix_idempotency_records_tenant_id", "idempotency_records", ["tenant_id"])
    op.create_index("ix_idempotency_records_subject", "idempotency_records", ["subject"])
    op.create_index("ix_idempotency_records_endpoint", "idempotency_records", ["endpoint"])
    op.create_index("ix_idempotency_records_key_digest", "idempotency_records", ["key_digest"])
    op.create_index("ix_idempotency_records_state", "idempotency_records", ["state"])
    op.create_index("ix_idempotency_records_created_at", "idempotency_records", ["created_at"])
    op.create_index("ix_idempotency_records_expires_at", "idempotency_records", ["expires_at"])
    op.create_table(
        "revoked_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("jti", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])
    op.execute(
        "UPDATE gateway_configs "
        "SET primary_provider = 'openai', "
        "primary_url = 'https://api.openai.com/v1/chat/completions', "
        "primary_key = '', primary_model = 'gpt-4o-mini', "
        "fallback_enabled = FALSE, fallback_provider = 'openai', "
        "fallback_url = '', fallback_key = '', fallback_model = 'gpt-4o-mini' "
        "WHERE primary_provider = 'mock' OR primary_key = 'env://MOCK_API_KEY'"
    )


def downgrade():
    op.drop_index("ix_revoked_tokens_expires_at", table_name="revoked_tokens")
    op.drop_table("revoked_tokens")
    op.drop_index("ix_idempotency_records_expires_at", table_name="idempotency_records")
    op.drop_index("ix_idempotency_records_created_at", table_name="idempotency_records")
    op.drop_index("ix_idempotency_records_state", table_name="idempotency_records")
    op.drop_index("ix_idempotency_records_key_digest", table_name="idempotency_records")
    op.drop_index("ix_idempotency_records_endpoint", table_name="idempotency_records")
    op.drop_index("ix_idempotency_records_subject", table_name="idempotency_records")
    op.drop_index("ix_idempotency_records_tenant_id", table_name="idempotency_records")
    op.drop_table("idempotency_records")
