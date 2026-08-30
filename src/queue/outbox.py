"""Database-backed notification/webhook outbox with retry and crash recovery."""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict
from ..config.settings import settings
from ..monitoring.database import OutboxEvent, SessionLocal
from ..providers.router_provider import validate_outbound_url
from ..secrets.field_crypto import decrypt_json, encrypt_json
from .notifications import get_notification_dispatcher

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 5


def enqueue_notification(session, *, recipient: str, subject: str, body: str, metadata: dict) -> None:
    payload = {"recipient": recipient, "subject": subject, "body": body, "metadata": metadata}
    session.add(OutboxEvent(
        topic="notification",
        payload_json=encrypt_json(payload),
        status="pending",
        available_at=datetime.utcnow(),
    ))


def enqueue_webhook(session, url: str, payload: Dict[str, Any]) -> None:
    """Enqueue a durable webhook POST. Pass session=None to manage its own."""
    _validate_webhook_url(url)
    own = session is None
    if own:
        session = SessionLocal()
    try:
        event = OutboxEvent(
            topic="webhook",
            payload_json=encrypt_json({"url": url, "json": payload}),
            status="pending",
            available_at=datetime.utcnow(),
        )
        session.add(event)
        if own:
            session.commit()
    finally:
        if own:
            session.close()


def _validate_webhook_url(url: str) -> None:
    try:
        validate_outbound_url(url, settings.webhook_egress_allowlist)
    except Exception as exc:
        raise ValueError("Webhook URL must be an allowed public HTTPS URL") from exc


async def _deliver_webhook(payload: Dict[str, Any], event_id: int) -> bool:
    import httpx
    try:
        _validate_webhook_url(payload.get("url", ""))
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.post(
                payload["url"],
                json=payload.get("json", {}),
                headers={"Idempotency-Key": f"outbox-{event_id}"},
            )
            return resp.status_code < 400
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("Webhook delivery failed for %s: %s", payload.get("url"), exc)
        return False


async def run_notification_outbox(stop_event: asyncio.Event) -> None:
    # ponytail: piggyback idempotency expiry sweep on the 1s tick (every ~60s)
    tick = 0
    while not stop_event.is_set():
        await deliver_next_notification()
        tick += 1
        if tick % 60 == 0:
            _sweep_expired_idempotency()
        if tick % 3600 == 0:
            _purge_expired_data()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass


def _purge_expired_data() -> None:
    from ..monitoring.database import purge_expired_data

    try:
        deleted = purge_expired_data()
        if deleted:
            logger.info("Purged %d expired records", deleted)
    except Exception as exc:
        logger.error("Retention purge failed: %s", exc)


def _sweep_expired_idempotency() -> None:
    """Delete completed idempotency records past their TTL (audit A8)."""
    from datetime import datetime as _dt
    from ..monitoring.database import IdempotencyRecord
    session = SessionLocal()
    try:
        deleted = session.query(IdempotencyRecord).filter(
            IdempotencyRecord.state == "completed",
            IdempotencyRecord.expires_at <= _dt.utcnow(),
        ).delete(synchronize_session=False)
        session.commit()
        if deleted:
            logger.info("Swept %d expired idempotency records", deleted)
    except Exception as exc:
        session.rollback()
        logger.error("Idempotency sweep failed: %s", exc)
    finally:
        session.close()


async def deliver_next_notification() -> bool:
    session = SessionLocal()
    now = datetime.utcnow()
    try:
        session.query(OutboxEvent).filter(OutboxEvent.status == "processing", OutboxEvent.lease_expires_at <= now).update({"status": "pending", "lease_expires_at": None}, synchronize_session=False)
        query = session.query(OutboxEvent).filter(
            OutboxEvent.status == "pending", OutboxEvent.available_at <= now
        ).order_by(OutboxEvent.id)
        if session.bind.dialect.name != "sqlite":
            query = query.with_for_update(skip_locked=True)
        event = query.first()
        if not event:
            session.commit(); return False
        event.status = "processing"
        event.attempts += 1
        event.lease_expires_at = now + timedelta(minutes=2)
        event_id = event.id
        topic = event.topic
        payload = decrypt_json(event.payload_json, {})
        if not payload:
            raise ValueError("Outbox payload cannot be decrypted")
        session.commit()
    except Exception:
        session.rollback(); return False
    finally:
        session.close()

    # ponytail: sync smtplib inside async send blocks the loop briefly — move into to_thread when email volume matters
    success = await get_notification_dispatcher().send(**payload) if topic == "notification" else await _deliver_webhook(payload, event_id)

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
