"""HTTP surface for the decision cache.

BIG-IP's per-request policy calls this on (effectively) every request via
an HTTP connector / iRule callout -- see docs/apm-integration.md. Kept to a
single cheap GET so it doesn't become the latency floor for every request
through APM.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.decision.cache import decision_cache
from app.security.auth import require_api_key

router = APIRouter(prefix="/internal/decision", tags=["decision"], dependencies=[Depends(require_api_key)])


@router.get("")
async def get_decision(subject_key: str) -> dict:
    record = decision_cache.get(subject_key)
    if record is None:
        # No cached signal is not an error -- it just means "nothing has
        # changed for this subject," which per-request policy should treat
        # as allow. 404 lets the Tcl side branch on HTTP status alone.
        raise HTTPException(status_code=404, detail="no active decision for subject")
    return record.model_dump()
