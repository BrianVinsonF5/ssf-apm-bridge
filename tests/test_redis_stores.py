"""Redis-backed store behavior.

STORE_BACKEND=redis is what the k8s manifests deploy, but the Redis classes
had no coverage at all -- only the in-memory ones were exercised. fakeredis
gives us the real client API (including bytes-vs-str decoding, which these
classes handle by hand) without needing a server.
"""
from __future__ import annotations

import fakeredis
import pytest

from app.correlation.store import InMemoryCorrelationStore, RedisCorrelationStore
from app.decision.cache import InMemoryDecisionCache, RedisDecisionCache
from app.models import CorrelationRecord, DecisionRecord
from app.replay_guard import RedisReplayStore, ReplayDetected, ReplayGuard

SUBJECT = "email:bob@example.com"
SESSION = "a1b2c3d4e5f6a1b2c3d4e5f6"


@pytest.fixture()
def redis_client():
    return fakeredis.FakeStrictRedis()


# --- correlation store -----------------------------------------------------


@pytest.fixture(params=["memory", "redis"])
def any_correlation_store(request, redis_client):
    """Run the same expectations against both backends so they can't drift."""
    if request.param == "memory":
        return InMemoryCorrelationStore()
    return RedisCorrelationStore(redis_client)


def test_register_then_lookup(any_correlation_store):
    any_correlation_store.register(CorrelationRecord(subject_key=SUBJECT, apm_session_id=SESSION))

    sessions = any_correlation_store.sessions_for(SUBJECT)

    assert [s.apm_session_id for s in sessions] == [SESSION]


def test_deregister_removes_the_session(any_correlation_store):
    any_correlation_store.register(CorrelationRecord(subject_key=SUBJECT, apm_session_id=SESSION))
    any_correlation_store.deregister(SESSION)

    assert any_correlation_store.sessions_for(SUBJECT) == []


def test_deregister_unknown_session_is_a_noop(any_correlation_store):
    any_correlation_store.deregister("does-not-exist-000000000")  # must not raise


def test_lookup_of_unknown_subject_is_empty(any_correlation_store):
    assert any_correlation_store.sessions_for("email:nobody@example.com") == []


def test_multiple_sessions_per_subject(any_correlation_store):
    """A user logged in from two devices maps to two sessions."""
    second = "b1b2c3d4e5f6a1b2c3d4e5f6"
    any_correlation_store.register(CorrelationRecord(subject_key=SUBJECT, apm_session_id=SESSION))
    any_correlation_store.register(CorrelationRecord(subject_key=SUBJECT, apm_session_id=second))

    assert {s.apm_session_id for s in any_correlation_store.sessions_for(SUBJECT)} == {SESSION, second}

    any_correlation_store.deregister(SESSION)
    assert {s.apm_session_id for s in any_correlation_store.sessions_for(SUBJECT)} == {second}


def test_redis_correlation_sets_a_ttl(redis_client):
    """Records must expire on their own; nothing sweeps Redis proactively."""
    store = RedisCorrelationStore(redis_client)
    store.register(CorrelationRecord(subject_key=SUBJECT, apm_session_id=SESSION))

    assert redis_client.ttl(f"ssf:corr:subject:{SUBJECT}") > 0
    assert redis_client.ttl(f"ssf:corr:session:{SESSION}") > 0


# --- decision cache --------------------------------------------------------


@pytest.fixture(params=["memory", "redis"])
def any_decision_cache(request, redis_client):
    if request.param == "memory":
        return InMemoryDecisionCache()
    return RedisDecisionCache(redis_client)


def test_decision_upsert_then_get(any_decision_cache):
    any_decision_cache.upsert(DecisionRecord(subject_key=SUBJECT, risk_level="HIGH", reason="breach"))

    cached = any_decision_cache.get(SUBJECT)

    assert cached.risk_level == "HIGH"
    assert cached.reason == "breach"


def test_decision_get_unknown_subject_is_none(any_decision_cache):
    assert any_decision_cache.get("email:nobody@example.com") is None


def test_decision_upsert_merges_with_existing_record(any_decision_cache):
    """Both backends must merge rather than replace, so a device-compliance
    signal doesn't erase a known risk level."""
    any_decision_cache.upsert(DecisionRecord(subject_key=SUBJECT, risk_level="HIGH"))
    any_decision_cache.upsert(DecisionRecord(subject_key=SUBJECT, device_compliant=False))

    cached = any_decision_cache.get(SUBJECT)

    assert cached.risk_level == "HIGH"
    assert cached.device_compliant is False


def test_redis_decision_sets_a_ttl(redis_client):
    cache = RedisDecisionCache(redis_client)
    cache.upsert(DecisionRecord(subject_key=SUBJECT, risk_level="HIGH"))

    assert redis_client.ttl(f"ssf:decision:{SUBJECT}") > 0


# --- replay guard ----------------------------------------------------------


def test_redis_replay_guard_detects_a_replayed_jti(redis_client):
    guard = ReplayGuard(RedisReplayStore(redis_client))

    guard.check_and_mark("jti-1")  # first sighting is fine

    with pytest.raises(ReplayDetected):
        guard.check_and_mark("jti-1")


def test_redis_replay_guard_allows_distinct_jtis(redis_client):
    guard = ReplayGuard(RedisReplayStore(redis_client))

    guard.check_and_mark("jti-1")
    guard.check_and_mark("jti-2")  # must not raise
