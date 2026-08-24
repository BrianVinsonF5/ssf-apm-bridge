"""jti replay protection.

A SET's `jti` must not be processed twice. Backed by the same pluggable
store abstraction as the correlation store / decision cache so a
multi-replica deployment shares one view via Redis.
"""
from __future__ import annotations

import time
from typing import Protocol

from app.config import settings


class ReplayStore(Protocol):
    def seen(self, jti: str) -> bool: ...
    def mark(self, jti: str, ttl_seconds: int) -> None: ...


class InMemoryReplayStore:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def _sweep(self) -> None:
        now = time.time()
        expired = [k for k, exp in self._seen.items() if exp <= now]
        for k in expired:
            del self._seen[k]

    def seen(self, jti: str) -> bool:
        self._sweep()
        return jti in self._seen

    def mark(self, jti: str, ttl_seconds: int) -> None:
        self._seen[jti] = time.time() + ttl_seconds


class RedisReplayStore:
    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def seen(self, jti: str) -> bool:
        return bool(self._redis.exists(f"ssf:jti:{jti}"))

    def mark(self, jti: str, ttl_seconds: int) -> None:
        self._redis.set(f"ssf:jti:{jti}", "1", ex=ttl_seconds)


class ReplayDetected(Exception):
    pass


class ReplayGuard:
    def __init__(self, store: ReplayStore) -> None:
        self._store = store

    def check_and_mark(self, jti: str) -> None:
        if self._store.seen(jti):
            raise ReplayDetected(f"jti {jti!r} already processed")
        self._store.mark(jti, settings.replay_jti_ttl_seconds)


def build_default_replay_guard() -> ReplayGuard:
    if settings.store_backend == "redis":
        import redis

        return ReplayGuard(RedisReplayStore(redis.from_url(settings.redis_url)))
    return ReplayGuard(InMemoryReplayStore())


replay_guard = build_default_replay_guard()
