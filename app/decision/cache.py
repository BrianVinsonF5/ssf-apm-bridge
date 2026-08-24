"""Continuous-path decision cache.

Keyed by subject, short TTL, read by BIG-IP's per-request policy on every
request (via the /internal/decision/{subject_key} lookup in api.py).
Writes merge into whatever's already cached for that subject rather than
replacing it wholesale, so a risk-level-change event doesn't clobber a
device-compliance-change that arrived a minute earlier for the same user.
"""
from __future__ import annotations

import json
import time
from typing import Protocol

from app.config import settings
from app.models import DecisionRecord


class DecisionCache(Protocol):
    def upsert(self, record: DecisionRecord) -> DecisionRecord: ...
    def get(self, subject_key: str) -> DecisionRecord | None: ...


class InMemoryDecisionCache:
    def __init__(self) -> None:
        self._records: dict[str, DecisionRecord] = {}

    def upsert(self, record: DecisionRecord) -> DecisionRecord:
        existing = self._records.get(record.subject_key)
        merged = _merge(existing, record)
        self._records[record.subject_key] = merged
        return merged

    def get(self, subject_key: str) -> DecisionRecord | None:
        record = self._records.get(subject_key)
        if record is None:
            return None
        if time.time() - record.updated_at > settings.decision_cache_ttl_seconds:
            del self._records[subject_key]
            return None
        return record


class RedisDecisionCache:
    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def _key(self, subject_key: str) -> str:
        return f"ssf:decision:{subject_key}"

    def upsert(self, record: DecisionRecord) -> DecisionRecord:
        existing = self.get(record.subject_key)
        merged = _merge(existing, record)
        self._redis.set(self._key(record.subject_key), merged.model_dump_json(), ex=settings.decision_cache_ttl_seconds)
        return merged

    def get(self, subject_key: str) -> DecisionRecord | None:
        raw = self._redis.get(self._key(subject_key))
        if raw is None:
            return None
        raw = raw.decode() if isinstance(raw, bytes) else raw
        return DecisionRecord.model_validate(json.loads(raw))


def _merge(existing: DecisionRecord | None, incoming: DecisionRecord) -> DecisionRecord:
    if existing is None:
        return incoming
    data = existing.model_dump()
    updates = incoming.model_dump(exclude_unset=False)
    for field in ("risk_level", "device_compliant", "assurance_level", "changed_claims", "reason", "source_event"):
        if updates.get(field) is not None:
            data[field] = updates[field]
    data["updated_at"] = incoming.updated_at
    return DecisionRecord.model_validate(data)


def build_default_decision_cache() -> DecisionCache:
    if settings.store_backend == "redis":
        import redis

        return RedisDecisionCache(redis.from_url(settings.redis_url))
    return InMemoryDecisionCache()


decision_cache = build_default_decision_cache()
