"""Database-backed notification/webhook outbox with retry and crash recovery."""
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from ..monitoring.database import OutboxEvent, SessionLocal
from .notifications import get_notification_dispatcher

_MAX_ATTEMPTS = 5


def enqueue_notification(session, *, recipient: str, subject: str, body: str, metadata: dict) -> None:
    session.add(OutboxEvent(topic="notification", payload_json=json.dumps({"recipient": recipient, "subject": subject, "body": body, "metadata": metadata}), status="pending", available_at=datetime.utcnow()))


def enqueue_webhook(session, url: str, payload: Dict[str, Any]) -> None:
    """Enqueue a durable webhook POST. Pass session=None to manage its own."""
    own = session is None
    if own:
        session = SessionLocal()
    try:
        event = OutboxEvent(
            topic="webhook",
            payload_json=json.dumps({"url": url, "json": payload}),
            status="pending",
            available_at=datetime.utcnow(),
        )
        session.add(event)
        if own:
            session.commit()
    finally:
        if own:
            session.close()


async def _deliver_webhook(payload: Dict[str, Any]) -> bool:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(payload["url"], json=payload.get("json", {}))
            return resp.status_code < 400
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("Webhook delivery failed for %s: %s", payload.get("url"), exc)
        return False


async def run_notification_outbox(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        await deliver_next_notification()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass


async def deliver_next_notification() -> bool:
    session = SessionLocal()
    now = datetime.utcnow()
    try:
        session.query(OutboxEvent).filter(OutboxEvent.status == "processing", OutboxEvent.lease_expires_at <= now).update({"status": "pending", "lease_expires_at": None}, synchronize_session=False)
        event = session.query(OutboxEvent).filter(OutboxEvent.status == "pending", OutboxEvent.available_at <= now).order_by(OutboxEvent.id).first()
        if not event:
            session.commit(); return False
        event.status = "processing"; event.attempts += 1; event.lease_expires_at = now + timedelta(minutes=2)
        event_id = event.id; topic = event.topic; payload = json.loads(event.payload_json); session.commit()
    except Exception:
        session.rollback(); return False
    finally:
        session.close()

    # ponytail: sync smtplib inside async send blocks the loop briefly — move into to_thread when email volume matters
    success = await get_notification_dispatcher().send(**payload) if topic == "notification" else await _deliver_webhook(payload)

    session = SessionLocal()
    try:
        event = session.query(OutboxEvent).filter(OutboxEvent.id == event_id, OutboxEvent.status == "processing").first()
        if event:
            if success:
                event.status = "completed"; event.completed_at = datetime.utcnow(); event.lease_expires_at = None
            elif event.attempts >= _MAX_ATTEMPTS:
                event.status = "dead_letter"; event.lease_expires_at = None; event.last_error = "delivery failed"
            else:
                event.status = "pending"; event.lease_expires_at = None; event.available_at = datetime.utcnow() + timedelta(seconds=2 ** event.attempts); event.last_error = "delivery failed"
            session.commit()
        return success
    except Exception:
        session.rollback(); return False
    finally:
        session.close()