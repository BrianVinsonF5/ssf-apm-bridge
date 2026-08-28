"""Shared control-plane auth for internal endpoints (admin, correlation,
decision lookup). Not part of the public push-receiver surface -- that one
authenticates the *caller* differently, by verifying the SET itself."""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from app.config import settings


async def require_api_key(x_api_key: str = Header(default="")) -> None:
    # Compare as bytes, not str: hmac.compare_digest raises TypeError on
    # str inputs containing non-ASCII characters, which would turn a
    # merely-wrong key into an unhandled 500 on every protected endpoint.
    presented = x_api_key.encode("utf-8", errors="replace")
    expected = settings.admin_api_key.encode("utf-8", errors="replace")
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing X-API-Key")
