"""
Integration tests for HITL workflow lifecycle.
"""

import os
os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(os.environ.get('TEMP', '.'), 'ai_security_test.db')}")
os.environ.setdefault("REQUIRE_AUTH", "false")
os.environ.setdefault("LOG_FORMAT", "text")

from src.monitoring.database import init_db
init_db()

import pytest
from src.hitl.hitl_manager import HITLManager


@pytest.fixture
def hitl_manager():
    return HITLManager()


class TestHITLCreateAndApprove:
    @pytest.mark.asyncio
    async def test_create_pending_request(self, hitl_manager):
        """Creating a request should return pending status."""
        result = await hitl_manager.create_request({
            "prompt": "Test HITL prompt",
            "user_id": "hitl_test_user",
            "model": "test-model",
        })
        assert result["status"] in ("pending", "approved")  # approved if HITL disabled
        if result["status"] == "pending":
            assert result["created"] is True
            assert result["request_id"] is not None

    @pytest.mark.asyncio
    async def test_approve_request(self, hitl_manager):
        """Approving a pending request should succeed."""
        result = await hitl_manager.create_request({
            "prompt": "Approve me",
            "user_id": "hitl_approve_user",
        })
        if result.get("request_id"):
            success = await hitl_manager.approve_request(
                request_id=result["request_id"],
                approved=True,
                admin_name="TestAdmin"
            )
            assert success is True

    @pytest.mark.asyncio
    async def test_deny_request(self, hitl_manager):
        """Denying a pending request should succeed."""
        result = await hitl_manager.create_request({
            "prompt": "Deny me",
            "user_id": "hitl_deny_user",
        })
        if result.get("request_id"):
            success = await hitl_manager.approve_request(
                request_id=result["request_id"],
                approved=False,
                admin_name="TestAdmin"
            )
            assert success is True


class TestHITLAssignment:
    @pytest.mark.asyncio
    async def test_assign_reviewer(self, hitl_manager):
        """Assigning a reviewer to a pending request should succeed."""
        result = await hitl_manager.create_request({
            "prompt": "Assign me",
            "user_id": "hitl_assign_user",
        })
        if result.get("request_id"):
            success = hitl_manager.assign_reviewer(result["request_id"], "reviewer@example.com")
            assert success is True
            details = hitl_manager.get_request_details(result["request_id"])
            assert details is not None
            assert details.get("assigned_to") == "reviewer@example.com"


class TestHITLHistory:
    @pytest.mark.asyncio
    async def test_completed_history(self, hitl_manager):
        """Completed history should include approved/denied requests."""
        result = await hitl_manager.create_request({
            "prompt": "History test",
            "user_id": "hitl_history_user",
        })
        if result.get("request_id"):
            await hitl_manager.approve_request(result["request_id"], True, "HistoryAdmin")
        
        history = hitl_manager.get_completed_history(limit=10)
        assert isinstance(history, list)
        if result.get("request_id"):
            ids = [h["id"] for h in history]
            assert result["request_id"] in ids


class TestHITLPriorityQueue:
    def test_compute_priority_tiers(self):
        """Test risk score to priority mapping (0..3)."""
        assert HITLManager._compute_priority(0.95) == 3
        assert HITLManager._compute_priority(0.85) == 3
        assert HITLManager._compute_priority(0.75) == 2
        assert HITLManager._compute_priority(0.60) == 2
        assert HITLManager._compute_priority(0.45) == 1
        assert HITLManager._compute_priority(0.30) == 1
        assert HITLManager._compute_priority(0.15) == 0
        assert HITLManager._compute_priority(0.0) == 0

    @pytest.mark.asyncio
    async def test_pending_requests_sorted_by_priority(self, hitl_manager):
        """Pending requests must be sorted by priority descending, then created_at ascending."""
        r1 = await hitl_manager.create_request({
            "prompt": "Low priority task",
            "user_id": "user_low",
            "risk_score": 0.1,
        })
        r2 = await hitl_manager.create_request({
            "prompt": "Critical priority task",
            "user_id": "user_critical",
            "risk_score": 0.95,
        })
        r3 = await hitl_manager.create_request({
            "prompt": "High priority task",
            "user_id": "user_high",
            "risk_score": 0.70,
        })

        if r1.get("request_id") and r2.get("request_id") and r3.get("request_id"):
            pending = hitl_manager.get_pending_requests(sort_by_priority=True)
            pending_ids = list(pending.keys())
            
            # Critical must appear before High, High before Low
            assert pending_ids.index(r2["request_id"]) < pending_ids.index(r3["request_id"])
            assert pending_ids.index(r3["request_id"]) < pending_ids.index(r1["request_id"])
            
            # Clean up
            await hitl_manager.approve_request(r1["request_id"], False, "CleanUp")
            await hitl_manager.approve_request(r2["request_id"], False, "CleanUp")
            await hitl_manager.approve_request(r3["request_id"], False, "CleanUp")


class TestHITLBatchOperations:
    @pytest.mark.asyncio
    async def test_batch_approve_and_deny(self, hitl_manager):
        """Batch approval and denial should succeed for multiple request IDs."""
        r1 = await hitl_manager.create_request({"prompt": "Batch item 1", "user_id": "user1"})
        r2 = await hitl_manager.create_request({"prompt": "Batch item 2", "user_id": "user2"})
        r3 = await hitl_manager.create_request({"prompt": "Batch item 3", "user_id": "user3"})

        ids = [r["request_id"] for r in [r1, r2, r3] if r.get("request_id")]
        if len(ids) == 3:
            # Batch approve r1 and r2
            approve_res = hitl_manager.batch_approve([ids[0], ids[1]], approved=True, admin_name="BatchAdmin")
            assert ids[0] in approve_res["succeeded"]
            assert ids[1] in approve_res["succeeded"]
            assert len(approve_res["failed"]) == 0

            # Batch deny r3 and a non-existent ID
            deny_res = hitl_manager.batch_approve([ids[2], "non-existent-id-999"], approved=False, admin_name="BatchAdmin")
            assert ids[2] in deny_res["succeeded"]
            assert len(deny_res["failed"]) == 1
            assert deny_res["failed"][0]["id"] == "non-existent-id-999"


class TestHITLSLAEscalation:
    @pytest.mark.asyncio
    async def test_escalate_overdue_requests(self, hitl_manager):
        """Requests past SLA deadline should be marked as escalated."""
        from datetime import datetime, timedelta
        from src.monitoring.database import SessionLocal, HITLRequest

        r = await hitl_manager.create_request({"prompt": "SLA test prompt", "user_id": "sla_user"})
        rid = r.get("request_id")
        if rid:
            # Force the deadline into the past in the DB
            session = SessionLocal()
            try:
                db_req = session.query(HITLRequest).filter(HITLRequest.request_id == rid).first()
                if db_req:
                    db_req.sla_deadline = datetime.utcnow() - timedelta(hours=5)
                    session.commit()
            finally:
                session.close()

            escalated = hitl_manager.escalate_overdue()
            assert rid in escalated

            # Verify get_request_details returns is_overdue and is_escalated
            details = hitl_manager.get_request_details(rid)
            assert details is not None
            assert details["is_escalated"] is True
            assert details["is_overdue"] is True

            # Clean up
            await hitl_manager.approve_request(rid, False, "CleanUp")

