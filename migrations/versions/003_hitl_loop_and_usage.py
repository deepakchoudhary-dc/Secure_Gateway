"""HITL callbacks/resume, token accounting columns, detection feedback table.

Revision ID: 003_hitl_loop_and_usage
Revises: 002_outbox_events
"""
from alembic import op
import sqlalchemy as sa

revision = "003_hitl_loop_and_usage"
down_revision = "002_outbox_events"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("hitl_requests", sa.Column("callback_url", sa.String(500), nullable=True))
    op.add_column("hitl_requests", sa.Column("resume_on_approval", sa.Boolean(), nullable=False, server_default=sa.false()))

    op.add_column("security_logs", sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("security_logs", sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("security_logs", sa.Column("total_tokens", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_security_logs_tenant_ts", "security_logs", ["tenant_id", "timestamp"])

    op.create_table(
        "detection_feedback",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, index=True),
        sa.Column("source", sa.String(50), nullable=False, index=True),
        sa.Column("label", sa.String(20), nullable=False, index=True),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.String(100), nullable=True, index=True),
    )


def downgrade():
    op.drop_table("detection_feedback")
    op.drop_index("ix_security_logs_tenant_ts", table_name="security_logs")
    op.drop_column("security_logs", "total_tokens")
    op.drop_column("security_logs", "completion_tokens")
    op.drop_column("security_logs", "prompt_tokens")
    op.drop_column("hitl_requests", "resume_on_approval")
    op.drop_column("hitl_requests", "callback_url")
