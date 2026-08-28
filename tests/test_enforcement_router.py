from __future__ import annotations

import logging

import pytest

from app.bigip.client import FastPathDisabled
from app.enforcement.router import handle_verified_set
from app.models import (
    KNOWN_EVENT_TYPES,
    CaepEventType,
    CorrelationRecord,
    EnforcementPath,
    RiscEventType,
    SecurityEventToken,
    SsfEventType,
    SubjectIdentifier,
)


def _set(event_type: str, payload: dict, subject_key_format: str = "email") -> SecurityEventToken:
    return SecurityEventToken(
        iss="https://idp.test",
        iat=1700000000,
        jti="jti-1",
        aud="https://bridge.test/events",
        sub_id=SubjectIdentifier(format=subject_key_format, email="bob@example.com"),
        events={event_type: payload},
    )


def test_session_revoked_is_fast_path_and_kills_correlated_session(correlation_store, decision_cache, monkeypatch):
    correlation_store.register(CorrelationRecord(subject_key="email:bob@example.com", apm_session_id="a1b2c3d4e5f6a1b2c3d4e5f6"))

    calls = []

    def fake_terminate(session_id, reason=""):
        calls.append((session_id, reason))

    import app.enforcement.router as router_mod

    monkeypatch.setattr(router_mod.bigip_client, "terminate_session", fake_terminate)

    set_ = _set(CaepEventType.SESSION_REVOKED.value, {"event_timestamp": 1700000000})
    result = router_mod.handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.path is EnforcementPath.FAST
    assert result.sessions_targeted == 1
    assert result.sessions_terminated == 1
    assert calls == [("a1b2c3d4e5f6a1b2c3d4e5f6", CaepEventType.SESSION_REVOKED.value)]
    # session should be deregistered after termination
    assert correlation_store.sessions_for("email:bob@example.com") == []


def test_session_revoked_with_no_correlated_session_is_a_noop(correlation_store, decision_cache):
    set_ = _set(CaepEventType.SESSION_REVOKED.value, {})
    result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.path is EnforcementPath.FAST
    assert result.sessions_targeted == 0
    assert result.sessions_terminated == 0


def test_fast_path_disabled_is_caught_not_raised(correlation_store, decision_cache):
    correlation_store.register(CorrelationRecord(subject_key="email:bob@example.com", apm_session_id="a1b2c3d4e5f6a1b2c3d4e5f6"))
    # BIGIP_ENABLE_FAST_PATH=false by default in the test env (see conftest)
    set_ = _set(CaepEventType.SESSION_REVOKED.value, {})

    result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.sessions_terminated == 0
    assert "disabled" in result.detail


def test_risk_level_change_is_continuous_path(correlation_store, decision_cache):
    set_ = _set(
        CaepEventType.RISK_LEVEL_CHANGE.value,
        {"current_level": "HIGH", "previous_level": "LOW", "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH"},
    )

    result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.path is EnforcementPath.CONTINUOUS
    cached = decision_cache.get("email:bob@example.com")
    assert cached.risk_level == "HIGH"
    assert cached.reason == "PASSWORD_FOUND_IN_DATA_BREACH"


def test_device_compliance_change_maps_to_bool(correlation_store, decision_cache):
    set_ = _set(
        CaepEventType.DEVICE_COMPLIANCE_CHANGE.value,
        {"current_status": "not-compliant", "previous_status": "compliant", "reason_user": {"en": "no longer trusted"}},
    )

    result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.path is EnforcementPath.CONTINUOUS
    cached = decision_cache.get("email:bob@example.com")
    assert cached.device_compliant is False
    assert cached.reason == "no longer trusted"


def test_session_established_is_informational(correlation_store, decision_cache):
    set_ = _set(CaepEventType.SESSION_ESTABLISHED.value, {})
    result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.path is EnforcementPath.INFORMATIONAL
    assert decision_cache.get("email:bob@example.com") is None


def test_unrecognized_event_type_is_informational_not_an_error(correlation_store, decision_cache):
    set_ = _set("https://schemas.openid.net/secevent/caep/event-type/does-not-exist", {})
    result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.path is EnforcementPath.INFORMATIONAL


def test_ssf_verification_event_is_recognized(correlation_store, decision_cache, caplog):
    """A stream health check must not be logged as an unrecognized type."""
    set_ = _set(SsfEventType.VERIFICATION.value, {"state": "abc123"})

    with caplog.at_level(logging.WARNING):
        result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.path is EnforcementPath.INFORMATIONAL
    assert "unrecognized_event_type" not in caplog.text
    assert SsfEventType.VERIFICATION.value in KNOWN_EVENT_TYPES


# --- multi-event SETs ------------------------------------------------------
# RFC 8417 allows a SET to carry several events. Acting on only the first
# silently dropped the rest -- a fail-open bug when the dropped event was the
# severe one.


def _multi_set(events: dict) -> SecurityEventToken:
    return SecurityEventToken(
        iss="https://idp.test",
        iat=1700000000,
        jti="jti-multi",
        aud="https://bridge.test/events",
        sub_id=SubjectIdentifier(format="email", email="bob@example.com"),
        events=events,
    )


def test_multi_event_set_acts_on_every_event(correlation_store, decision_cache, monkeypatch):
    """A session-revoked bundled with a risk-level-change must still kill the
    session AND update the decision cache."""
    correlation_store.register(
        CorrelationRecord(subject_key="email:bob@example.com", apm_session_id="a1b2c3d4e5f6a1b2c3d4e5f6")
    )

    calls = []
    import app.enforcement.router as router_mod

    monkeypatch.setattr(
        router_mod.bigip_client, "terminate_session", lambda session_id, reason="": calls.append((session_id, reason))
    )

    set_ = _multi_set(
        {
            CaepEventType.RISK_LEVEL_CHANGE.value: {"current_level": "HIGH", "risk_reason": "breach"},
            CaepEventType.SESSION_REVOKED.value: {"event_timestamp": 1700000000},
        }
    )
    result = router_mod.handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    # fast path is the most severe path taken, so that's what's reported
    assert result.path is EnforcementPath.FAST
    assert result.sessions_terminated == 1
    assert calls == [("a1b2c3d4e5f6a1b2c3d4e5f6", CaepEventType.SESSION_REVOKED.value)]
    # ...and the continuous-path event was not dropped
    assert decision_cache.get("email:bob@example.com").risk_level == "HIGH"


def test_multi_event_set_reports_all_event_types(correlation_store, decision_cache):
    set_ = _multi_set(
        {
            CaepEventType.SESSION_ESTABLISHED.value: {},
            CaepEventType.RISK_LEVEL_CHANGE.value: {"current_level": "MEDIUM"},
        }
    )
    result = handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert CaepEventType.SESSION_ESTABLISHED.value in result.event_type
    assert CaepEventType.RISK_LEVEL_CHANGE.value in result.event_type
    # continuous outranks informational
    assert result.path is EnforcementPath.CONTINUOUS


def test_fast_path_detail_reports_every_session_outcome(correlation_store, decision_cache, monkeypatch):
    """Regression: `detail` was overwritten per session, so with a mix of
    successes and failures it reported only the last one."""
    for sid in ("a1b2c3d4e5f6a1b2c3d4e5f6", "b1b2c3d4e5f6a1b2c3d4e5f6"):
        correlation_store.register(CorrelationRecord(subject_key="email:bob@example.com", apm_session_id=sid))

    import app.enforcement.router as router_mod
    from app.bigip.client import BigIpError

    def flaky(session_id, reason=""):
        if session_id.startswith("a"):
            return None
        raise BigIpError("boom")

    monkeypatch.setattr(router_mod.bigip_client, "terminate_session", flaky)

    set_ = _set(CaepEventType.SESSION_REVOKED.value, {})
    result = router_mod.handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.sessions_targeted == 2
    assert result.sessions_terminated == 1
    assert "terminated 1" in result.detail
    assert "1 failed" in result.detail


def test_account_disabled_purges_correlation_even_when_termination_fails(
    correlation_store, decision_cache, monkeypatch
):
    """The account is locked, so a mapping we couldn't act on is worse than
    none: it must not linger and retarget later signals."""
    correlation_store.register(
        CorrelationRecord(subject_key="email:bob@example.com", apm_session_id="a1b2c3d4e5f6a1b2c3d4e5f6")
    )

    import app.enforcement.router as router_mod
    from app.bigip.client import BigIpError

    def always_fails(session_id, reason=""):
        raise BigIpError("boom")

    monkeypatch.setattr(router_mod.bigip_client, "terminate_session", always_fails)

    set_ = _set(RiscEventType.ACCOUNT_DISABLED.value, {"reason": "hijacking"})
    result = router_mod.handle_verified_set(set_, correlation=correlation_store, decisions=decision_cache)

    assert result.sessions_terminated == 0
    assert correlation_store.sessions_for("email:bob@example.com") == []
    assert "purged" in result.detail
