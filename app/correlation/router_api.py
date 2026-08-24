"""HTTP surface for the correlation store.

BIG-IP calls this from an iRule bound to ACCESS_SESSION_STARTED (register)
and ACCESS_SESSION_CLOSED (deregister) -- see docs/apm-integration.md for
the Tcl. Nothing here is reachable without X-API-Key.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.correlation.store import correlation_store
from app.models import CorrelationRecord, SubjectIdentifier
from app.security.auth import require_api_key

router = APIRouter(prefix="/correlation", tags=["correlation"], dependencies=[Depends(require_api_key)])


class RegisterSessionBody(SubjectIdentifier):
    apm_session_id: str
    bigip_device: str | None = None
    apm_username: str | None = None


@router.post("/sessions", status_code=201)
async def register_session(body: RegisterSessionBody) -> dict:
    subject = SubjectIdentifier.model_validate(body.model_dump(exclude={"apm_session_id", "bigip_device", "apm_username"}))
    record = CorrelationRecord(
        subject_key=subject.correlation_key(),
        apm_session_id=body.apm_session_id,
        bigip_device=body.bigip_device,
        apm_username=body.apm_username,
    )
    correlation_store.register(record)
    return {"status": "registered", "subject_key": record.subject_key}


@router.delete("/sessions/{apm_session_id}", status_code=204, response_model=None)
async def deregister_session(apm_session_id: str) -> None:
    correlation_store.deregister(apm_session_id)


@router.post("/sessions/lookup")
async def lookup_sessions(subject: SubjectIdentifier) -> dict:
    key = subject.correlation_key()
    records = correlation_store.sessions_for(key)
    if not records:
        raise HTTPException(status_code=404, detail="no sessions registered for this subject")
    return {"subject_key": key, "sessions": [r.model_dump() for r in records]}
