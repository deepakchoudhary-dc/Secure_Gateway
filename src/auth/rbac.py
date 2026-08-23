"""Role-Based Access Control (RBAC) guards for FastAPI endpoints."""

import logging
from typing import Callable

from fastapi import Depends, HTTPException, status

from .tenant import CurrentUser, get_current_user

logger = logging.getLogger(__name__)


def require_role(*allowed_roles: str) -> Callable:
    """Return a FastAPI dependency that enforces one-of role membership.

    Admins always pass. Example::

        dependencies=[Depends(require_role("reviewer"))]
    """

    async def _guard(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.has_role("admin"):
            return current_user
        for role in allowed_roles:
            if current_user.has_role(role):
                return current_user
        logger.warning(
            "RBAC denied: user=%s tenant=%s roles=%s required=%s",
            current_user.subject, current_user.tenant_id, current_user.roles, allowed_roles,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of roles: {', '.join(allowed_roles)}",
        )

    return _guard
