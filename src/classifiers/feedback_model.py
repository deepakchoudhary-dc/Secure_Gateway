"""
Detection feedback store — the learning loop's labeled examples.

HITL decisions and red-team outcomes are persisted here as (prompt, label)
samples. Malicious samples feed back into the semantic jailbreak detector's
template set, so paraphrases of confirmed attacks get blocked without a
redeploy. Benign approvals are stored for future allow-list / calibration use.
"""

import logging
from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy import Column, DateTime, Integer, String, Text, func

from ..monitoring.database import Base, SessionLocal

logger = logging.getLogger(__name__)

LEARNED_TEMPLATE_LIMIT = 50


class DetectionFeedback(Base):
    __tablename__ = "detection_feedback"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String(50), nullable=False, index=True)  # hitl_denied | hitl_approved | redteam
    label = Column(String(20), nullable=False, index=True)  # malicious | benign
    prompt = Column(Text, nullable=False)
    tenant_id = Column(String(100), nullable=True, index=True)


def record_feedback(source: str, label: str, prompt: str, tenant_id: Optional[str] = None) -> None:
    """Store one labeled sample. Best-effort: never raises into the caller."""
    if not prompt:
        return
    session = SessionLocal()
    try:
        session.add(DetectionFeedback(
            source=source,
            label=label,
            prompt=prompt[:10000],
            tenant_id=tenant_id,
            created_at=datetime.utcnow(),
        ))
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Failed to record detection feedback: %s", exc)
    finally:
        session.close()


def get_learned_malicious_prompts(tenant_id: Optional[str], limit: int = LEARNED_TEMPLATE_LIMIT) -> List[str]:
    """Recent malicious prompts for a tenant (+ global), newest first.

    Fed into the semantic detector alongside configured jailbreak templates.
    """
    from sqlalchemy import or_
    session = SessionLocal()
    try:
        rows = (
            session.query(DetectionFeedback.prompt)
            .filter(
                DetectionFeedback.label == "malicious",
                or_(
                    DetectionFeedback.tenant_id == tenant_id,
                    DetectionFeedback.tenant_id.is_(None),
                ),
            )
            .order_by(DetectionFeedback.id.desc())
            .limit(limit)
            .all()
        )
        return [r[0] for r in rows]
    except Exception as exc:
        logger.error("Failed to load learned prompts: %s", exc)
        return []
    finally:
        session.close()


def get_feedback_epoch() -> Tuple[int, int]:
    """Cheap cache-invalidation token: (max_id, row_count)."""
    session = SessionLocal()
    try:
        max_id = session.query(func.max(DetectionFeedback.id)).scalar() or 0
        count = session.query(func.count(DetectionFeedback.id)).scalar() or 0
        return int(max_id), int(count)
    except Exception:
        return (0, 0)
    finally:
        session.close()
