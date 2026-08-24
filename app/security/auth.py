"""Shared control-plane auth for internal endpoints (admin, correlation,
decision lookup). Not part of the public push-receiver surface -- that one
authenticates the *caller* differently, by verifying the SET itself."""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from app.config import settings


async def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_api_key, settings.admin_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing X-API-Key")
