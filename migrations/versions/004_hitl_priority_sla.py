"""HITL priority queue, SLA escalation, batch review

Revision ID: 004_hitl_priority_sla
Revises: 003_hitl_loop_and_usage
"""
from alembic import op
import sqlalchemy as sa

revision = "004_hitl_priority_sla"
down_revision = "003_hitl_loop_and_usage"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("hitl_requests", sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("hitl_requests", sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"))
    op.add_column("hitl_requests", sa.Column("sla_deadline", sa.DateTime(), nullable=True))
    op.create_index("ix_hitl_requests_priority", "hitl_requests", ["priority"])
    op.create_index("ix_hitl_requests_sla_deadline", "hitl_requests", ["sla_deadline"])


def downgrade():
    op.drop_index("ix_hitl_requests_sla_deadline", table_name="hitl_requests")
    op.drop_index("ix_hitl_requests_priority", table_name="hitl_requests")
    op.drop_column("hitl_requests", "sla_deadline")
    op.drop_column("hitl_requests", "risk_score")
    op.drop_column("hitl_requests", "priority")
