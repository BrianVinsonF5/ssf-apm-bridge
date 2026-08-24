from __future__ import annotations

import os

os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")
os.environ.setdefault("RECEIVER_BASE_URL", "https://bridge.test")
os.environ.setdefault("BIGIP_HOST", "bigip.test")
os.environ.setdefault("BIGIP_USERNAME", "svc")
os.environ.setdefault("BIGIP_PASSWORD", "svc")
os.environ.setdefault("BIGIP_ENABLE_FAST_PATH", "false")
os.environ.setdefault("STORE_BACKEND", "memory")

import pytest
from jwt import PyJWK

from app.correlation.store import InMemoryCorrelationStore
from app.decision.cache import InMemoryDecisionCache
from app.replay_guard import InMemoryReplayStore, ReplayGuard
from app.security.jwks import jwks_manager
from app.ssf.registry import TransmitterConfig, TransmitterRegistry
from tests.fixtures.sample_sets import generate_rsa_keypair, jwk_public

TEST_ISSUER = "https://idp.test"
TEST_AUDIENCE = "https://bridge.test/events"
TEST_KID = "test-key-1"


@pytest.fixture()
def rsa_keypair():
    return generate_rsa_keypair()


@pytest.fixture()
def transmitter_registry(rsa_keypair):
    registry = TransmitterRegistry()
    registry.register(
        TransmitterConfig(
            issuer=TEST_ISSUER,
            jwks_uri=f"{TEST_ISSUER}/.well-known/jwks.json",
            configuration_endpoint=f"{TEST_ISSUER}/ssf/stream",
            status_endpoint=f"{TEST_ISSUER}/ssf/status",
            add_subject_endpoint=f"{TEST_ISSUER}/ssf/subjects/add",
            remove_subject_endpoint=f"{TEST_ISSUER}/ssf/subjects/remove",
            verification_endpoint=f"{TEST_ISSUER}/ssf/verify",
            stream_id="test-stream-1",
            expected_audience=TEST_AUDIENCE,
        )
    )
    return registry


class _StubJwksClient:
    def __init__(self, key: PyJWK):
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> PyJWK:
        return self._key


@pytest.fixture()
def register_signing_key(rsa_keypair, monkeypatch):
    """Point the (singleton) jwks_manager at our in-memory test key instead
    of doing a real network fetch."""
    jwk_dict = jwk_public(rsa_keypair, TEST_KID)
    pyjwk = PyJWK(jwk_dict, algorithm="RS256")
    stub = _StubJwksClient(pyjwk)
    monkeypatch.setattr(jwks_manager, "_client_for", lambda issuer: stub)
    return pyjwk


@pytest.fixture()
def correlation_store():
    return InMemoryCorrelationStore()


@pytest.fixture()
def decision_cache():
    return InMemoryDecisionCache()


@pytest.fixture()
def replay_guard():
    return ReplayGuard(InMemoryReplayStore())
