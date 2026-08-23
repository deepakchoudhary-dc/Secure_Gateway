"""
Tenant and user identity models with FastAPI dependency injection.

Provides the ``get_current_user`` dependency that extracts identity
from either a JWT bearer token or a legacy API key, depending on
``AUTH_MODE``.
"""

import hashlib
import logging
import re
import secrets
from typing import List, Optional

from fastapi import Header, HTTPException, status

from ..config.settings import settings
from .jwt_auth import TokenError, decode_access_token

logger = logging.getLogger(__name__)

# Same charset as user_id validation in the gateway router
_CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")


class CurrentUser:
    """Lightweight identity object propagated through request processing."""

    __slots__ = ("subject", "tenant_id", "roles", "auth_method")

    def __init__(self, subject: str, tenant_id: str, roles: List[str], auth_method: str = "jwt"):
        self.subject = subject
        self.tenant_id = tenant_id
        self.roles = roles
        self.auth_method = auth_method

    def has_role(self, role: str) -> bool:
        return role in self.roles or "admin" in self.roles

    def __repr__(self) -> str:
        return f"<CurrentUser subject={self.subject!r} tenant={self.tenant_id!r} roles={self.roles!r}>"


def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_admin_token: Optional[str] = Header(default=None),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
) -> CurrentUser:
    """Resolve the calling identity from either JWT or legacy API-key."""
    auth_mode = getattr(settings, "AUTH_MODE", "api_key")

    # JWT path
    if auth_mode == "jwt":
        token = _extract_bearer_token(authorization)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
        try:
            claims = decode_access_token(token)
        except TokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
        return CurrentUser(
            subject=claims["sub"],
            tenant_id=claims["tenant_id"],
            roles=claims.get("roles", []),
            auth_method="jwt",
        )

    # Legacy API-key path (default for development)
    if not settings.REQUIRE_AUTH:
        return CurrentUser(subject="anonymous", tenant_id="default", roles=["admin"], auth_method="api_key")

    if not settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication is not configured")

    # Check admin token first
    if x_admin_token and settings.ADMIN_API_KEY and secrets.compare_digest(x_admin_token, settings.ADMIN_API_KEY):
        return CurrentUser(subject="admin", tenant_id="default", roles=["admin"], auth_method="api_key")

    # Check user API key
    if x_api_key and secrets.compare_digest(x_api_key, settings.API_KEY):
        # Determine if admin via user key when allowed
        roles = ["user"]
        if settings.ALLOW_ADMIN_AUTH_VIA_USER_KEY and x_api_key == settings.ADMIN_API_KEY:
            roles = ["admin"]

        # Per-identity quota buckets instead of one shared "api_key_user":
        # - X-Client-ID declares the caller behind a shared credential;
        # - otherwise the bucket is derived from the credential itself.
        # ponytail: client-id is self-declared (rotatable for fresh quotas) —
        # a hashed-key credential registry is the upgrade path.
        if x_client_id:
            if not _CLIENT_ID_PATTERN.fullmatch(x_client_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="X-Client-ID must be 1-64 characters of [A-Za-z0-9_.:@-]",
                )
            subject = f"apikey:{x_client_id}"
        else:
            subject = f"apikey:{hashlib.sha256(x_api_key.encode()).hexdigest()[:12]}"

        return CurrentUser(subject=subject, tenant_id="default", roles=roles, auth_method="api_key")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
