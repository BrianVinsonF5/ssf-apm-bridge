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
from app.models import CaepEventType, DecisionRecord, EnforcementPath, RiscEventType, SecurityEventToken

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
}


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
    event_type = set_.primary_event_type()
    payload = set_.primary_event_payload()
    subject_key = set_.sub_id.correlation_key()
    path = EVENT_PATHS.get(event_type, EnforcementPath.INFORMATIONAL)

    if event_type not in EVENT_PATHS:
        logger.warning("unrecognized_event_type: %s (subject=%s) -- treated as informational", event_type, subject_key)

    result = EnforcementResult(event_type=event_type, path=path, subject_key=subject_key)

    if path is EnforcementPath.FAST:
        sessions = correlation.sessions_for(subject_key)
        result.sessions_targeted = len(sessions)
        if not sessions:
            result.detail = "no correlated APM session for this subject -- nothing to terminate"
            logger.info("fast_path_no_session: event=%s subject=%s", event_type, subject_key)
            return result
        for record in sessions:
            try:
                bigip_client.terminate_session(record.apm_session_id, reason=event_type)
                correlation.deregister(record.apm_session_id)
                result.sessions_terminated += 1
            except FastPathDisabled:
                result.detail = "fast path disabled (BIGIP_ENABLE_FAST_PATH=false) -- logged only"
            except BigIpError:
                logger.exception("fast_path_termination_failed: session=%s", record.apm_session_id)
                result.detail = "termination call to BIG-IP failed; see logs"

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
