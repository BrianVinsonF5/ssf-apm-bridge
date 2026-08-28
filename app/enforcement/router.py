"""Event -> enforcement path dispatch.

This is the mapping table from the reference architecture, as code. Field
names pulled from each event's payload are copied from the literal JSON
examples in the CAEP 1.0 final spec:
https://openid.net/specs/openid-caep-1_0-final.html
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.bigip.client import BigIpError, FastPathDisabled, bigip_client
from app.correlation.store import CorrelationStore, correlation_store
from app.decision.cache import DecisionCache, decision_cache
from app.models import (
    CaepEventType,
    DecisionRecord,
    EnforcementPath,
    RiscEventType,
    SecurityEventToken,
    SsfEventType,
)

logger = logging.getLogger("ssf_bridge.enforcement")

# --- the mapping table -----------------------------------------------------

EVENT_PATHS: dict[str, EnforcementPath] = {
    CaepEventType.SESSION_REVOKED: EnforcementPath.FAST,
    CaepEventType.TOKEN_CLAIMS_CHANGE: EnforcementPath.CONTINUOUS,
    CaepEventType.CREDENTIAL_CHANGE: EnforcementPath.CONTINUOUS,
    CaepEventType.ASSURANCE_LEVEL_CHANGE: EnforcementPath.CONTINUOUS,
    CaepEventType.DEVICE_COMPLIANCE_CHANGE: EnforcementPath.CONTINUOUS,
    CaepEventType.SESSION_ESTABLISHED: EnforcementPath.INFORMATIONAL,
    CaepEventType.SESSION_PRESENTED: EnforcementPath.INFORMATIONAL,
    CaepEventType.RISK_LEVEL_CHANGE: EnforcementPath.CONTINUOUS,
    # RISC: severity calls are judgment calls documented inline; override
    # freely via `EVENT_PATHS[...] = ...` at import time if yours differ.
    RiscEventType.ACCOUNT_CREDENTIAL_CHANGE_REQUIRED: EnforcementPath.FAST,  # force re-auth with new creds
    RiscEventType.ACCOUNT_PURGED: EnforcementPath.FAST,
    RiscEventType.ACCOUNT_DISABLED: EnforcementPath.FAST,
    RiscEventType.ACCOUNT_ENABLED: EnforcementPath.INFORMATIONAL,  # re-auth still required through the IdP
    RiscEventType.IDENTIFIER_CHANGED: EnforcementPath.INFORMATIONAL,  # TODO: remap correlation store, not modeled in MVP
    RiscEventType.IDENTIFIER_RECYCLED: EnforcementPath.INFORMATIONAL,
    RiscEventType.OPT_IN: EnforcementPath.INFORMATIONAL,
    RiscEventType.OPT_OUT_INITIATED: EnforcementPath.INFORMATIONAL,
    RiscEventType.OPT_OUT_CANCELLED: EnforcementPath.INFORMATIONAL,
    RiscEventType.OPT_OUT_EFFECTIVE: EnforcementPath.INFORMATIONAL,
    RiscEventType.RECOVERY_ACTIVATED: EnforcementPath.CONTINUOUS,  # flag for step-up while recovery is in progress
    RiscEventType.RECOVERY_INFORMATION_CHANGED: EnforcementPath.INFORMATIONAL,
    RiscEventType.SESSIONS_REVOKED: EnforcementPath.FAST,
    # SSF stream management: a verification echo proves the delivery channel
    # works. No subject state, so nothing to enforce -- but mapping it keeps
    # stream health checks out of the "unrecognized event type" warnings.
    SsfEventType.VERIFICATION: EnforcementPath.INFORMATIONAL,
}


#: Fast-path events for which the subject's correlation records should be
#: dropped even when no live APM session was found -- the account is gone or
#: locked, so any stale mapping is worse than useless.
_PURGE_CORRELATION_EVENTS: frozenset[str] = frozenset(
    {
        RiscEventType.ACCOUNT_PURGED.value,
        RiscEventType.ACCOUNT_DISABLED.value,
    }
)


@dataclass
class EnforcementResult:
    event_type: str
    path: EnforcementPath
    subject_key: str
    sessions_targeted: int = 0
    sessions_terminated: int = 0
    detail: str = ""


def _decision_record_for(event_type: str, subject_key: str, payload: dict[str, Any]) -> DecisionRecord:
    record = DecisionRecord(subject_key=subject_key, source_event=event_type)

    if event_type == CaepEventType.RISK_LEVEL_CHANGE:
        record.risk_level = payload.get("current_level")
        record.reason = payload.get("risk_reason")
    elif event_type == CaepEventType.DEVICE_COMPLIANCE_CHANGE:
        record.device_compliant = payload.get("current_status") == "compliant"
        record.reason = _localized(payload.get("reason_admin")) or _localized(payload.get("reason_user"))
    elif event_type == CaepEventType.ASSURANCE_LEVEL_CHANGE:
        record.assurance_level = payload.get("current_level")
        record.reason = f"namespace={payload.get('namespace')} direction={payload.get('change_direction')}"
    elif event_type == CaepEventType.TOKEN_CLAIMS_CHANGE:
        record.changed_claims = payload.get("claims")
        record.reason = _localized(payload.get("reason_admin")) or _localized(payload.get("reason_user"))
    elif event_type == CaepEventType.CREDENTIAL_CHANGE:
        record.reason = f"{payload.get('change_type')} {payload.get('credential_type')}".strip()
    elif event_type == RiscEventType.RECOVERY_ACTIVATED:
        record.reason = "account recovery flow activated"
    else:
        record.reason = event_type

    return record


def _localized(reason: dict[str, str] | None) -> str | None:
    if not reason:
        return None
    return reason.get("en") or next(iter(reason.values()), None)


def handle_verified_set(
    set_: SecurityEventToken,
    *,
    correlation: CorrelationStore = correlation_store,
    decisions: DecisionCache = decision_cache,
) -> EnforcementResult:
    """Dispatch every event carried by a verified SET.

    RFC 8417 permits a SET to carry more than one event, and acting on only
    the first would silently drop the rest -- including, in the worst case, a
    `session-revoked` bundled alongside a lower-severity signal. Each event is
    dispatched independently; the returned result summarizes the SET as a
    whole and reports the *most severe* path taken (fast > continuous >
    informational) so callers and logs reflect the strongest action applied.
    """
    subject_key = set_.sub_id.correlation_key()
    results = [
        _handle_one_event(event_type, payload or {}, subject_key, correlation, decisions)
        for event_type, payload in set_.events.items()
    ]

    if len(results) > 1:
        logger.info(
            "multi_event_set_processed: count=%d subject=%s types=%s",
            len(results),
            subject_key,
            ",".join(r.event_type for r in results),
        )

    return _summarize(results, subject_key)


_PATH_SEVERITY: dict[EnforcementPath, int] = {
    EnforcementPath.INFORMATIONAL: 0,
    EnforcementPath.CONTINUOUS: 1,
    EnforcementPath.FAST: 2,
}


def _summarize(results: list[EnforcementResult], subject_key: str) -> EnforcementResult:
    """Collapse per-event results into one, keeping the most severe path."""
    if not results:
        # Unreachable via verify_set (which rejects an empty `events` claim),
        # but a directly-constructed SET could get here.
        return EnforcementResult(
            event_type="",
            path=EnforcementPath.INFORMATIONAL,
            subject_key=subject_key,
            detail="SET carried no events",
        )
    if len(results) == 1:
        return results[0]

    most_severe = max(results, key=lambda r: _PATH_SEVERITY[r.path])
    return EnforcementResult(
        event_type=",".join(r.event_type for r in results),
        path=most_severe.path,
        subject_key=subject_key,
        sessions_targeted=max(r.sessions_targeted for r in results),
        sessions_terminated=sum(r.sessions_terminated for r in results),
        detail=" | ".join(f"{r.event_type.rsplit('/', 1)[-1]}: {r.detail}" for r in results if r.detail),
    )


def _handle_one_event(
    event_type: str,
    payload: dict[str, Any],
    subject_key: str,
    correlation: CorrelationStore,
    decisions: DecisionCache,
) -> EnforcementResult:
    path = EVENT_PATHS.get(event_type, EnforcementPath.INFORMATIONAL)

    if event_type not in EVENT_PATHS:
        logger.warning("unrecognized_event_type: %s (subject=%s) -- treated as informational", event_type, subject_key)

    result = EnforcementResult(event_type=event_type, path=path, subject_key=subject_key)

    if path is EnforcementPath.FAST:
        _enforce_fast(event_type, subject_key, correlation, result)
    elif path is EnforcementPath.CONTINUOUS:
        record = _decision_record_for(event_type, subject_key, payload)
        decisions.upsert(record)
        result.detail = f"decision cache updated: {record.model_dump(exclude={'subject_key', 'updated_at'})}"
    else:
        result.detail = "informational event, logged only"

    logger.info(
        "event_processed: type=%s path=%s subject=%s targeted=%d terminated=%d detail=%s",
        event_type,
        path.value,
        subject_key,
        result.sessions_targeted,
        result.sessions_terminated,
        result.detail,
    )
    return result


def _enforce_fast(
    event_type: str,
    subject_key: str,
    correlation: CorrelationStore,
    result: EnforcementResult,
) -> None:
    sessions = correlation.sessions_for(subject_key)
    result.sessions_targeted = len(sessions)

    if not sessions:
        result.detail = "no correlated APM session for this subject -- nothing to terminate"
        logger.info("fast_path_no_session: event=%s subject=%s", event_type, subject_key)
        return

    # Collect per-session outcomes instead of overwriting a single `detail`,
    # which previously reported only whichever branch the last session hit.
    terminated: list[str] = []
    disabled: list[str] = []
    failed: list[str] = []

    for record in sessions:
        try:
            bigip_client.terminate_session(record.apm_session_id, reason=event_type)
            correlation.deregister(record.apm_session_id)
            result.sessions_terminated += 1
            terminated.append(record.apm_session_id)
        except FastPathDisabled:
            disabled.append(record.apm_session_id)
        except BigIpError:
            logger.exception("fast_path_termination_failed: session=%s", record.apm_session_id)
            failed.append(record.apm_session_id)

    # account-purged / account-disabled mean the account itself is gone or
    # locked, so a mapping we couldn't act on is worse than no mapping at all:
    # drop it regardless of whether the kill call succeeded, was skipped, or
    # failed. Otherwise a stale session id lingers until the TTL expires and
    # every later signal for that subject retargets a session that cannot be
    # terminated.
    if event_type in _PURGE_CORRELATION_EVENTS:
        for session_id in disabled + failed:
            correlation.deregister(session_id)

    details: list[str] = []
    if terminated:
        details.append(f"terminated {len(terminated)}")
    if disabled:
        details.append(
            f"{len(disabled)} skipped: fast path disabled (BIGIP_ENABLE_FAST_PATH=false) -- logged only"
        )
    if failed:
        details.append(f"{len(failed)} failed: termination call to BIG-IP failed; see logs")
    if event_type in _PURGE_CORRELATION_EVENTS and (disabled or failed):
        details.append(f"purged {len(disabled) + len(failed)} stale correlation record(s)")
    result.detail = "; ".join(details)
