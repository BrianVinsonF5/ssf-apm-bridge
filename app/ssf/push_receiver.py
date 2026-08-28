"""Push delivery endpoint (RFC 8935).

Per the SSF spec a receiver should acknowledge quickly and do the real
work asynchronously; here "asynchronously" means an in-process background
task, which is enough for an MVP's throughput. Swap for a queue (SQS,
Redis Streams, whatever you already run) before this sees production
volume -- the handoff point is the one line calling `handle_verified_set`.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Request, Response, status

from app.enforcement.router import handle_verified_set
from app.replay_guard import ReplayDetected, replay_guard
from app.security.set_verifier import SetVerificationError, verify_set
from app.ssf.registry import transmitter_registry

logger = logging.getLogger("ssf_bridge.push_receiver")

router = APIRouter(tags=["ssf"])


def _process(raw_token: str) -> None:
    """Verify and dispatch one SET.

    Runs in a background task *after* the transmitter has already been sent
    its 202, so an exception escaping this function is invisible to the
    transmitter and the event is gone for good. Everything is therefore
    caught and logged here rather than allowed to propagate.
    """
    try:
        try:
            set_ = verify_set(raw_token, transmitter_registry)
        except SetVerificationError:
            logger.exception("set_verification_failed")
            return

        try:
            replay_guard.check_and_mark(set_.jti)
        except ReplayDetected:
            logger.warning("replay_detected: jti=%s iss=%s", set_.jti, set_.iss)
            return

        handle_verified_set(set_)
    except Exception:  # noqa: BLE001 - last line of defense for a background task
        # A store outage, a malformed payload that slipped past validation,
        # a BIG-IP client bug -- none of it should take down the worker
        # silently. Log loudly; the transmitter will not retry.
        logger.exception("set_processing_failed_unexpectedly")


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def receive_set(request: Request, background_tasks: BackgroundTasks) -> Response:
    """RFC 8935 push delivery: the transmitter POSTs a bare SET JWT as the
    request body with Content-Type: application/secevent+jwt."""
    body = await request.body()
    raw_token = body.decode("utf-8").strip()

    if not raw_token:
        return Response(status_code=status.HTTP_400_BAD_REQUEST, content="empty body")

    # Verification happens in the background so we can return 202 fast, but
    # a malformed token that fails the *cheapest* structural check (not
    # even a well-formed JWT) is worth rejecting synchronously -- it's
    # almost always a misconfigured transmitter, not something to retry.
    if raw_token.count(".") != 2:
        return Response(status_code=status.HTTP_400_BAD_REQUEST, content="not a JWT")

    background_tasks.add_task(_process, raw_token)
    return Response(status_code=status.HTTP_202_ACCEPTED)
