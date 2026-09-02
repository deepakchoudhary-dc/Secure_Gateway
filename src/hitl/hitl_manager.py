"""
Human-in-the-Loop (HITL) Management Module - Connected to SQLite database Locally

Enhanced with:
- Real notification dispatch (email/webhook/log)
- Reviewer assignment
- Expiration and escalation
- Completed review history
"""

import asyncio
import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from ..config.settings import settings
from ..monitoring.database import SessionLocal, HITLRequest, OutboxEvent
from ..queue.outbox import enqueue_notification, enqueue_webhook
from ..classifiers.feedback_model import record_feedback
from ..secrets.field_crypto import encrypt_json

logger = logging.getLogger(__name__)


class HITLManager:
    def __init__(self):
        self.approval_timeout = settings.HITL_APPROVAL_TIMEOUT_SECONDS

    @staticmethod
    def _compute_priority(risk_score: float) -> int:
        # 4-tier priority from risk_score; per-request override via request_data.priority if provided
        if risk_score >= 0.85:
            return 3  # critical
        if risk_score >= 0.6:
            return 2  # high
        if risk_score >= 0.3:
            return 1  # medium
        return 0  # low

    async def create_request(self, request_data: Any, risk_score: float = 0.0) -> Dict[str, Any]:
        """
        Create a human approval request and return immediately.
        """
        if not settings.HITL_ENABLED:
            return {
                "request_id": None,
                "status": "approved",
                "approved": True,
                "blocking": False,
                "created": False,
                "reason": "HITL is disabled"
            }

        request_id = self._generate_request_id()
        fields = self._extract_request_fields(request_data)
        # allow risk_score from request_data or explicit param
        try:
            rs = float(fields.get("risk_score", risk_score) or risk_score)
        except Exception:
            rs = float(risk_score or 0.0)
        priority = fields.get("priority")
        if priority is None:
            priority = self._compute_priority(rs)
        else:
            try:
                priority = int(priority)
            except Exception:
                priority = self._compute_priority(rs)
        priority = max(0, min(3, int(priority)))
        sla_deadline = None
        try:
            sla_hours = int(getattr(settings, "HITL_SLA_HOURS", 4) or 4)
            if sla_hours > 0:
                from datetime import timedelta, timezone
                sla_deadline = datetime.utcnow() + timedelta(hours=sla_hours)
        except Exception:
            sla_deadline = None

        session = SessionLocal()
        try:
            db_request = HITLRequest(
                request_id=request_id,
                prompt=fields["prompt"],
                system_prompt=fields["system_prompt"],
                retrieved_context=fields["retrieved_context"],
                context=fields["context"],
                model=fields["model"],
                user_id=fields["user_id"],
                status="pending",
                notification_sent=False,
                callback_url=fields.get("callback_url"),
                resume_on_approval=fields.get("resume_on_approval", False),
                priority=priority,
                risk_score=float(rs),
                sla_deadline=sla_deadline,
                created_at=datetime.utcnow()
            )
            session.add(db_request)
            enqueue_notification(
                session,
                recipient=settings.HITL_EMAIL,
                subject=f"[AI Security Gateway] HITL Review Required: {request_id}",
                body=f"A request requires human review.\n\nRequest ID: {request_id}\nUser: {fields['user_id']}",
                metadata={"request_id": request_id, "user_id": fields["user_id"]},
            )
            session.commit()
            logger.info(f"Created HITL pending request: {request_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save HITL request: {e}")
            return {
                "request_id": request_id,
                "status": "error",
                "approved": False,
                "blocking": False,
                "created": False,
                "error": "failed_to_create_hitl_request"
            }
        finally:
            session.close()

        return {
            "request_id": request_id,
            "status": "pending",
            "approved": False,
            "blocking": False,
            "created": True
            }

    async def request_approval(self, request_data: Any, risk_score: float = 0.0) -> Dict[str, Any]:
        """
        Request human approval for high-risk requests.

        Production default is non-blocking: create a pending request and return
        request_id/status immediately. Set HITL_BLOCKING_WAIT=true to opt in to
        the legacy wait-for-decision behavior.
        """
        if not settings.HITL_BLOCKING_WAIT:
            return await self.create_request(request_data, risk_score=risk_score)

        return await self._request_approval_blocking_result(request_data, risk_score=risk_score)

    async def request_approval_blocking(self, request_data: Any) -> bool:
        """
        Boolean compatibility method for callers that need a decision before continuing.
        Respects HITL_APPROVAL_TIMEOUT_SECONDS for the maximum wait.
        """
        return bool(await self._request_approval_blocking_result(request_data))

    async def _request_approval_blocking_result(self, request_data: Any, risk_score: float = 0.0) -> Dict[str, Any]:
        """Create a HITL request and block until a decision or timeout."""
        created = await self.create_request(request_data, risk_score=risk_score)
        if created.get("status") != "pending":
            return created

        request_id = created["request_id"]

        # Wait for approval with timeout
        try:
            approved = await asyncio.wait_for(
                self._wait_for_approval(request_id),
                timeout=self.approval_timeout
            )
            return {
                "request_id": request_id,
                "status": "approved" if approved else "denied",
                "approved": approved,
                "blocking": True,
                "created": True
            }
        except asyncio.TimeoutError:
            logger.warning(f"Approval timeout for request {request_id}")
            self._mark_timeout(request_id)
            return {
                "request_id": request_id,
                "status": "timeout",
                "approved": False,
                "blocking": True,
                "created": True
            }

    def _extract_request_fields(self, request_data: Any) -> Dict[str, Any]:
        """Normalize dict and pydantic-style request objects into audit fields."""
        def field(name: str, default: str = "") -> str:
            if isinstance(request_data, dict):
                value = request_data.get(name, default)
            else:
                value = getattr(request_data, name, default)
            return value if value is not None else default

        def opt(name: str):
            if isinstance(request_data, dict):
                return request_data.get(name)
            return getattr(request_data, name, None)

        return {
            "prompt": field("prompt"),
            "system_prompt": field("system_prompt"),
            "retrieved_context": field("retrieved_context"),
            "context": field("context"),
            "model": field("model", "unknown"),
            "user_id": field("user_id", "unknown"),
            "callback_url": opt("callback_url"),
            "resume_on_approval": bool(opt("resume_on_approval")),
            "risk_score": opt("risk_score") if opt("risk_score") is not None else opt("security_score"),
            "priority": opt("priority"),
        }

    def _mark_timeout(self, request_id: str):
        """Mark a pending request as timed out."""
        db_session = SessionLocal()
        try:
            db_req = db_session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            if db_req and db_req.status == "pending":
                db_req.status = "timeout"
                db_req.decision_at = datetime.utcnow()
                db_session.commit()
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error saving HITL timeout: {e}")
        finally:
            db_session.close()

    def _generate_request_id(self) -> str:
        """Generate unguessable request ID"""
        return f"hitl_{uuid.uuid4().hex}"

    async def _wait_for_approval(self, request_id: str) -> bool:
        """Wait for human approval by polling the SQLite database"""
        while True:
            await asyncio.sleep(2)  # Check DB every 2 seconds
            session = SessionLocal()
            try:
                db_req = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
                if db_req:
                    if db_req.status == "approved":
                        return True
                    elif db_req.status in ["denied", "timeout"]:
                        return False
            except Exception as e:
                logger.error(f"Error checking HITL status: {e}")
            finally:
                session.close()

    async def approve_request(self, request_id: str, approved: bool, admin_name: str = "Admin") -> bool:
        """Approve or deny a pending request — atomic and durable."""
        session = SessionLocal()
        try:
            # Atomic compare-and-set: only pending can transition
            updated = session.query(HITLRequest).filter(
                HITLRequest.request_id == request_id,
                HITLRequest.status == "pending"
            ).update({
                HITLRequest.status: "approved" if approved else "denied",
                HITLRequest.decision_by: admin_name,
                HITLRequest.decision_at: datetime.now(timezone.utc),
            }, synchronize_session=False)
            if updated == 0:
                session.rollback()
                return False
            db_req = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            snapshot = {
                "request_id": db_req.request_id,
                "prompt": db_req.prompt,
                "system_prompt": db_req.system_prompt,
                "retrieved_context": db_req.retrieved_context,
                "model": db_req.model or "unknown",
                "user_id": db_req.user_id or "unknown",
                "tenant_id": db_req.tenant_id,
                "callback_url": db_req.callback_url,
                "resume_on_approval": bool(db_req.resume_on_approval),
            }
            # Learning loop
            try:
                record_feedback(
                    source="hitl_denied" if not approved else "hitl_approved",
                    label="malicious" if not approved else "benign",
                    prompt=db_req.prompt,
                    tenant_id=db_req.tenant_id,
                )
            except Exception:
                pass
            if snapshot["callback_url"]:
                enqueue_webhook(session, snapshot["callback_url"], {
                    "type": "hitl_decision",
                    "request_id": request_id,
                    "approved": approved,
                    "decision_by": admin_name,
                    "decided_at": datetime.now(timezone.utc).isoformat(),
                }, tenant_id=snapshot["tenant_id"])
            # Durable resume: enqueue to outbox instead of fire-and-forget task
            if approved and snapshot["resume_on_approval"] and snapshot["callback_url"]:
                session.add(OutboxEvent(
                    topic="hitl_resume",
                    payload_json=encrypt_json(snapshot),
                    status="pending",
                    available_at=datetime.now(timezone.utc),
                    tenant_id=snapshot["tenant_id"],
                ))
            session.commit()
            logger.info(f"Request {request_id} manually {'approved' if approved else 'denied'} by {admin_name}")
            return True
        except Exception:
            session.rollback()
            logger.exception("Failed to approve request %s", request_id)
            return False
        finally:
            session.close()

    async def _resume_and_notify(self, snap: Dict[str, Any]) -> bool:
        """Re-run an approved request through the gateway and POST the result.

        Invoked by the outbox worker for `hitl_resume` events, so a crash
        between approval and resume no longer loses the run: the event is
        retried with backoff and dead-letters after max attempts.
        Returns True when the resume pipeline ran and the result webhook
        was enqueued; False so the outbox retries.
        """
        try:
            from ..gateway.router import AIRequest, process_ai_request_impl  # local: circular import
            from ..auth.tenant import CurrentUser

            req = AIRequest(
                prompt=snap["prompt"],
                system_prompt=snap["system_prompt"],
                retrieved_context=snap["retrieved_context"],
                model=snap["model"],
                user_id=snap["user_id"],
            )
            user = CurrentUser(subject=snap["user_id"], tenant_id=snap["tenant_id"] or "default", roles=["user"])
            response = await process_ai_request_impl(req, current_user=user, hitl_exempt=True)
            enqueue_webhook(None, snap["callback_url"], {
                "type": "hitl_result",
                "request_id": snap["request_id"],
                "response": response.model_dump(),
            }, tenant_id=snap.get("tenant_id"))
            return True
        except Exception as exc:
            logger.exception("HITL resume failed for %s", snap.get("request_id"))
            return False

    def assign_reviewer(self, request_id: str, reviewer: str) -> bool:
        """Assign a reviewer to a pending request."""
        session = SessionLocal()
        try:
            db_req = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            if db_req and db_req.status == "pending":
                db_req.assigned_to = reviewer
                session.commit()
                logger.info("Request %s assigned to %s", request_id, reviewer)
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error("Failed to assign reviewer for %s: %s", request_id, e)
            return False
        finally:
            session.close()

    def get_pending_requests(self, sort_by_priority: bool = True, tenant_id: Optional[str] = None) -> Dict[str, Dict]:
        """Get all pending approval requests from DB, priority queue sorted, tenant-scoped if needed"""
        session = SessionLocal()
        try:
            query = session.query(HITLRequest).filter(HITLRequest.status == "pending")
            if tenant_id:
                query = query.filter(HITLRequest.tenant_id == tenant_id)
            if sort_by_priority and getattr(settings, "HITL_PRIORITY_ENABLED", True):
                query = query.order_by(HITLRequest.priority.desc(), HITLRequest.created_at.asc())
            else:
                query = query.order_by(HITLRequest.created_at.asc())
            db_reqs = query.all()
            now = datetime.utcnow()
            result = {}
            for r in db_reqs:
                is_overdue = bool(getattr(r, "sla_deadline", None) and r.sla_deadline and r.sla_deadline < now)
                is_escalated = bool(getattr(r, "escalated_at", None))
                result[r.request_id] = {
                    "id": r.request_id,
                    "prompt": r.prompt,
                    "context": r.context,
                    "model": r.model,
                    "user_id": r.user_id,
                    "timestamp": r.created_at.isoformat(),
                    "status": r.status,
                    "assigned_to": getattr(r, "assigned_to", None),
                    "notification_sent": getattr(r, "notification_sent", False),
                    "priority": getattr(r, "priority", 0) or 0,
                    "risk_score": getattr(r, "risk_score", 0.0) or 0.0,
                    "sla_deadline": r.sla_deadline.isoformat() if getattr(r, "sla_deadline", None) else None,
                    "is_overdue": is_overdue,
                    "is_escalated": is_escalated,
                }
            return result
        except Exception as e:
            logger.error(f"Error fetching pending requests: {e}")
            return {}
        finally:
            session.close()

    def batch_approve(self, request_ids: List[str], approved: bool, admin_name: str = "Admin") -> Dict[str, Any]:
        """Batch approve/deny multiple requests. Returns summary."""
        results = {"succeeded": [], "failed": [], "total": len(request_ids)}
        now = datetime.utcnow()
        session = SessionLocal()
        try:
            for rid in request_ids:
                try:
                    updated = session.query(HITLRequest).filter(
                        HITLRequest.request_id == rid,
                        HITLRequest.status == "pending"
                    ).update({
                        HITLRequest.status: "approved" if approved else "denied",
                        HITLRequest.decision_by: admin_name,
                        HITLRequest.decision_at: now,
                    }, synchronize_session=False)

                    if updated == 0:
                        results["failed"].append({"id": rid, "reason": "not found or not pending"})
                        continue

                    db_req = session.query(HITLRequest).filter(HITLRequest.request_id == rid).first()
                    if db_req:
                        prompt_val = db_req.prompt
                        tenant_id_val = db_req.tenant_id
                        callback_url_val = db_req.callback_url
                        resume_val = bool(db_req.resume_on_approval)
                        model_val = db_req.model or "unknown"
                        user_id_val = db_req.user_id or "unknown"
                        sys_prompt_val = db_req.system_prompt
                        context_val = db_req.retrieved_context

                        # record feedback
                        try:
                            record_feedback(
                                source="hitl_denied" if not approved else "hitl_approved",
                                label="malicious" if not approved else "benign",
                                prompt=prompt_val,
                                tenant_id=tenant_id_val,
                            )
                        except Exception:
                            pass

                        # Webhook notification
                        if callback_url_val:
                            try:
                                enqueue_webhook(session, callback_url_val, {
                                    "type": "hitl_decision",
                                    "request_id": rid,
                                    "approved": approved,
                                    "decision_by": admin_name,
                                    "decided_at": now.isoformat(),
                                }, tenant_id=tenant_id_val)
                            except Exception:
                                pass

                        # Durable resume on approval
                        if approved and resume_val and callback_url_val:
                            snapshot = {
                                "request_id": rid,
                                "prompt": prompt_val,
                                "system_prompt": sys_prompt_val,
                                "retrieved_context": context_val,
                                "model": model_val,
                                "user_id": user_id_val,
                                "tenant_id": tenant_id_val,
                                "callback_url": callback_url_val,
                                "resume_on_approval": resume_val,
                            }
                            session.add(OutboxEvent(
                                topic="hitl_resume",
                                payload_json=encrypt_json(snapshot),
                                status="pending",
                                available_at=now,
                                tenant_id=tenant_id_val,
                            ))

                    session.commit()
                    results["succeeded"].append(rid)
                except Exception as item_err:
                    session.rollback()
                    logger.error(f"Batch approve DB error for {rid}: {item_err}")
                    results["failed"].append({"id": rid, "reason": str(item_err)})
        finally:
            session.close()
        return results

    def escalate_overdue(self) -> List[str]:
        """SLA escalation: mark overdue pending requests as escalated. Returns escalated ids."""
        try:
            sla_hours = int(getattr(settings, "HITL_SLA_HOURS", 4) or 4)
            if sla_hours <= 0:
                return []
        except Exception:
            return []
        now = datetime.utcnow()
        session = SessionLocal()
        try:
            overdue = session.query(HITLRequest).filter(
                HITLRequest.status == "pending",
                HITLRequest.sla_deadline.isnot(None),
                HITLRequest.sla_deadline < now,
                HITLRequest.escalated_at.is_(None)
            ).all()
            escalated_ids = []
            for r in overdue:
                r.escalated_at = now
                # assign to escalation email if configured
                esc_email = getattr(settings, "HITL_ESCALATION_EMAIL", "") or getattr(settings, "HITL_EMAIL", "")
                if esc_email:
                    try:
                        enqueue_notification(
                            session,
                            recipient=esc_email,
                            subject=f"[ESCALATED] HITL Review Overdue: {r.request_id}",
                            body=f"Request {r.request_id} breached SLA ({sla_hours}h). Prompt: {r.prompt[:500]}",
                            metadata={"request_id": r.request_id, "escalated": True},
                        )
                    except Exception:
                        pass
                escalated_ids.append(r.request_id)
            if escalated_ids:
                session.commit()
                logger.warning(f"SLA escalated {len(escalated_ids)} overdue HITL requests")
            return escalated_ids
        except Exception as e:
            session.rollback()
            logger.error(f"Error escalating overdue HITL requests: {e}")
            return []
        finally:
            session.close()

    def get_request_details(self, request_id: str) -> Optional[Dict]:
        """Get details of a specific request"""
        session = SessionLocal()
        try:
            r = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            if r:
                now = datetime.utcnow()
                is_overdue = bool(getattr(r, "sla_deadline", None) and r.sla_deadline and r.sla_deadline < now and r.status == "pending")
                return {
                    "id": r.request_id,
                    "prompt": r.prompt,
                    "context": r.context,
                    "model": r.model,
                    "user_id": r.user_id,
                    "timestamp": r.created_at.isoformat(),
                    "status": r.status,
                    "decision_by": r.decision_by,
                    "decision_at": r.decision_at.isoformat() if r.decision_at else None,
                    "assigned_to": getattr(r, "assigned_to", None),
                    "escalated_at": r.escalated_at.isoformat() if getattr(r, "escalated_at", None) else None,
                    "notification_sent": getattr(r, "notification_sent", False),
                    "priority": getattr(r, "priority", 0) or 0,
                    "risk_score": getattr(r, "risk_score", 0.0) or 0.0,
                    "sla_deadline": r.sla_deadline.isoformat() if getattr(r, "sla_deadline", None) else None,
                    "is_overdue": is_overdue,
                    "is_escalated": bool(getattr(r, "escalated_at", None)),
                }
            return None
        except Exception as e:
            logger.error(f"Error fetching request details: {e}")
            return None
        finally:
            session.close()

    def get_completed_history(self, limit: int = 50, offset: int = 0, tenant_id: Optional[str] = None) -> List[Dict]:
        """Get completed (approved/denied/timeout) review history."""
        session = SessionLocal()
        try:
            query = session.query(HITLRequest).filter(
                HITLRequest.status.in_(["approved", "denied", "timeout"])
            )
            if tenant_id:
                query = query.filter(HITLRequest.tenant_id == tenant_id)
            db_reqs = (
                query.order_by(HITLRequest.decision_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return [{
                "id": r.request_id,
                "user_id": r.user_id,
                "model": r.model,
                "status": r.status,
                "decision_by": r.decision_by,
                "decision_at": r.decision_at.isoformat() if r.decision_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "assigned_to": getattr(r, "assigned_to", None),
                "priority": getattr(r, "priority", 0) or 0,
                "risk_score": getattr(r, "risk_score", 0.0) or 0.0,
            } for r in db_reqs]
        except Exception as e:
            logger.error("Error fetching HITL history: %s", e)
            return []
        finally:
            session.close()

