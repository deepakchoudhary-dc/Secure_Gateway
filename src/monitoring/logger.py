"""
Monitoring and Logging Module - Connected to SQLite database
"""

import contextvars
import logging
import logging.handlers
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import json
from ..config.settings import settings
from ..monitoring.database import SessionLocal, SecurityLog

logger = logging.getLogger(__name__)

# ── Request ID context ─────────────────────────────────────────────────
_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set the request ID for the current async context.  Returns the ID."""
    rid = request_id or uuid.uuid4().hex[:16]
    _request_id_var.set(rid)
    return rid


def get_request_id() -> str:
    """Get the current request ID."""
    return _request_id_var.get("")

SENSITIVE_KEY_PATTERN = re.compile(r"(key|token|secret|password|credential|authorization|cookie)", re.IGNORECASE)
SECRET_VALUE_PATTERNS = [
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"), "[REDACTED OPENAI KEY]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"AQ\.[A-Za-z0-9_-]{30,}"), "[REDACTED GEMINI KEY]"),
    (re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}"), "Authorization: Bearer [REDACTED]"),
    (re.compile(r"(?i)(?:api_key|apikey|password|secret|private_key|token|passwd|db_password)\s*[:=]\s*['\"]?[^'\"\s]{6,}['\"]?"), "[REDACTED CREDENTIAL]"),
]


def redact_for_log(value: Any, max_string: int = 500) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if SENSITIVE_KEY_PATTERN.search(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_for_log(item, max_string=max_string)
        return redacted
    if isinstance(value, list):
        return [redact_for_log(item, max_string=max_string) for item in value[:50]]
    if isinstance(value, str):
        result = value
        for pattern, replacement in SECRET_VALUE_PATTERNS:
            result = pattern.sub(replacement, result)
        if len(result) > max_string:
            return result[:max_string] + "...[TRUNCATED]"
        return result
    return value

def log_transaction(
    user_id: str,
    prompt: str,
    response: Optional[str],
    risk_score: float,
    flagged: bool,
    duration: float,
    anomalies: List[Dict],
    action_taken: str,
    client_ip: Optional[str] = "127.0.0.1",
    system_prompt: Optional[str] = None,
    retrieved_context: Optional[str] = None,
    trace: Optional[List[Dict]] = None,
    tenant_id: Optional[str] = None,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    total_tokens: int = 0,
):
    """
    Log a complete security transaction to the SQLite database
    """
    # Console output
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": get_request_id(),
        "user_id": user_id,
        "tenant_id": tenant_id,
        "prompt_len": len(prompt),
        "response_len": len(response) if response else 0,
        "risk_score": risk_score,
        "flagged": flagged,
        "duration": duration,
        "anomalies": redact_for_log(anomalies),
        "trace_steps": len(trace) if trace else 0,
        "action_taken": action_taken
    }
    logger.info(f"Gateway Transaction: {json.dumps(log_entry)}")

    # Sensitive fields are encrypted before persistence when enabled.
    from ..secrets.field_crypto import encrypt_field, encrypt_json
    session = SessionLocal()
    try:
        db_log = SecurityLog(
            user_id=user_id,
            prompt=encrypt_field(prompt),
            system_prompt=encrypt_field(system_prompt),
            retrieved_context=encrypt_field(retrieved_context),
            response=encrypt_field(response),
            risk_score=risk_score,
            flagged=flagged,
            duration=duration,
            anomalies=encrypt_json(anomalies),
            trace_json=encrypt_json(trace or []),
            action_taken=action_taken,
            client_ip=client_ip,
            request_id=get_request_id() or None,
            tenant_id=tenant_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            timestamp=datetime.now(timezone.utc)
        )
        session.add(db_log)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to write transaction to SQLite: {e}")
    finally:
        session.close()

class AnomalyDetector:
    def __init__(self):
        self.baseline_metrics = {
            "avg_request_length": 150,
            "avg_processing_time": 0.5,
            "normal_patterns": []
        }

    def detect_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies in requests based on sizes, processing speeds, or repetitive words
        """
        anomalies = []
        severity = "low"

        # Check request length
        prompt = request_data.get("prompt", "")
        if prompt:
            length = len(prompt)
            if length > self.baseline_metrics["avg_request_length"] * 3:
                anomalies.append({
                    "type": "unusual_length",
                    "value": length,
                    "threshold": self.baseline_metrics["avg_request_length"] * 3,
                    "description": f"Prompt length ({length}) exceeds normal threshold"
                })
                severity = "medium"

        # Check for unusual patterns or characters (e.g. repeated characters indicative of token smash)
        if prompt:
            prompt_lower = prompt.lower()
            suspicious_patterns = ["repeat", "loop", "infinite", "bomb", "ignore previous"]
            for pattern in suspicious_patterns:
                if pattern in prompt_lower:
                    anomalies.append({
                        "type": "suspicious_pattern",
                        "pattern": pattern,
                        "description": f"Prompt contains suspicious keyword pattern: '{pattern}'"
                    })
                    severity = "high"

        return {
            "anomalies": anomalies,
            "severity": severity,
            "detected": len(anomalies) > 0
        }

# Global anomaly detector instance
anomaly_detector = AnomalyDetector()

class StructuredJsonFormatter(logging.Formatter):
    """Structured JSON log formatter with request ID injection."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": get_request_id(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging():
    """Setup logging configuration with optional structured JSON format."""
    import os
    os.makedirs("logs", exist_ok=True)
    log_level = getattr(logging, settings.normalized_log_level())

    log_format = getattr(settings, "LOG_FORMAT", "text")

    if log_format == "json":
        formatter = StructuredJsonFormatter()
    else:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = logging.handlers.RotatingFileHandler(
        "logs/ai_security.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logging.basicConfig(
        level=log_level,
        handlers=[file_handler, stream_handler],
    )
    logging.getLogger("watchfiles").setLevel(logging.WARNING)

def detect_anomaly(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to detect anomalies"""
    return anomaly_detector.detect_anomaly(request_data)
