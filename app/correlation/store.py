"""Subject <-> APM session correlation.

This is the piece the reference architecture calls out as "the real work":
an incoming SET's `sub_id` has to resolve to a live APM session id before
the fast path can terminate anything. BIG-IP populates this store itself,
via an iRule on ACCESS_SESSION_STARTED/CLOSED calling the registration API
in app/correlation/router_api.py -- see docs/apm-integration.md.

A subject can map to more than one session (a user logged in from two
devices), so lookups return a list.
"""
from __future__ import annotations

import json
import time
from typing import Protocol

from app.config import settings
from app.models import CorrelationRecord


class CorrelationStore(Protocol):
    def register(self, record: CorrelationRecord) -> None: ...
    def deregister(self, apm_session_id: str) -> None: ...
    def sessions_for(self, subject_key: str) -> list[CorrelationRecord]: ...


class InMemoryCorrelationStore:
    def __init__(self) -> None:
        # subject_key -> {apm_session_id: CorrelationRecord}
        self._by_subject: dict[str, dict[str, CorrelationRecord]] = {}
        # reverse index for O(1) deregister by session id alone
        self._session_to_subject: dict[str, str] = {}

    def register(self, record: CorrelationRecord) -> None:
        self._by_subject.setdefault(record.subject_key, {})[record.apm_session_id] = record
        self._session_to_subject[record.apm_session_id] = record.subject_key

    def deregister(self, apm_session_id: str) -> None:
        subject_key = self._session_to_subject.pop(apm_session_id, None)
        if subject_key and subject_key in self._by_subject:
            self._by_subject[subject_key].pop(apm_session_id, None)
            if not self._by_subject[subject_key]:
                del self._by_subject[subject_key]

    def sessions_for(self, subject_key: str) -> list[CorrelationRecord]:
        self._sweep_expired(subject_key)
        return list(self._by_subject.get(subject_key, {}).values())

    def _sweep_expired(self, subject_key: str) -> None:
        cutoff = time.time() - settings.correlation_ttl_seconds
        records = self._by_subject.get(subject_key, {})
        expired = [sid for sid, rec in records.items() if rec.registered_at < cutoff]
        for sid in expired:
            self.deregister(sid)


class RedisCorrelationStore:
    """Same semantics, backed by a Redis hash per subject plus a reverse
    lookup key so a bare session id can be deregistered without knowing
    its subject."""

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def _subject_hash_key(self, subject_key: str) -> str:
        return f"ssf:corr:subject:{subject_key}"

    def _session_key(self, apm_session_id: str) -> str:
        return f"ssf:corr:session:{apm_session_id}"

    def register(self, record: CorrelationRecord) -> None:
        ttl = settings.correlation_ttl_seconds
        payload = record.model_dump_json()
        self._redis.hset(self._subject_hash_key(record.subject_key), record.apm_session_id, payload)
        self._redis.expire(self._subject_hash_key(record.subject_key), ttl)
        self._redis.set(self._session_key(record.apm_session_id), record.subject_key, ex=ttl)

    def deregister(self, apm_session_id: str) -> None:
        subject_key = self._redis.get(self._session_key(apm_session_id))
        if subject_key is None:
            return
        subject_key = subject_key.decode() if isinstance(subject_key, bytes) else subject_key
        self._redis.hdel(self._subject_hash_key(subject_key), apm_session_id)
        self._redis.delete(self._session_key(apm_session_id))

    def sessions_for(self, subject_key: str) -> list[CorrelationRecord]:
        raw = self._redis.hgetall(self._subject_hash_key(subject_key))
        records = []
        for _, payload in raw.items():
            payload = payload.decode() if isinstance(payload, bytes) else payload
            records.append(CorrelationRecord.model_validate(json.loads(payload)))
        return records


def build_default_correlation_store() -> CorrelationStore:
    if settings.store_backend == "redis":
        import redis

        return RedisCorrelationStore(redis.from_url(settings.redis_url))
    return InMemoryCorrelationStore()


correlation_store = build_default_correlation_store()
