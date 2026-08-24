from __future__ import annotations

import pytest

from app.bigip.client import FastPathDisabled
from app.enforcement.router import handle_verified_set
from app.models import CaepEventType, CorrelationRecord, EnforcementPath, SecurityEventToken, SubjectIdentifier


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
