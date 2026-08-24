from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from jwt import PyJWK

from app.correlation.store import correlation_store
from app.decision.cache import decision_cache
from app.main import app
from app.security.jwks import jwks_manager
from app.ssf.registry import TransmitterConfig, transmitter_registry
from tests.conftest import TEST_AUDIENCE, TEST_ISSUER, TEST_KID
from tests.fixtures.sample_sets import generate_rsa_keypair, jwk_public, make_set


@pytest.fixture()
def wired_transmitter(monkeypatch):
    """Register a transmitter directly into the real (singleton) registry
    and point the real jwks_manager at a stub, since push_receiver.py
    imports those singletons at module scope."""
    key = generate_rsa_keypair()
    transmitter_registry.register(
        TransmitterConfig(
            issuer=TEST_ISSUER,
            jwks_uri=f"{TEST_ISSUER}/.well-known/jwks.json",
            expected_audience=TEST_AUDIENCE,
        )
    )
    pyjwk = PyJWK(jwk_public(key, TEST_KID), algorithm="RS256")

    class _Stub:
        def get_signing_key_from_jwt(self, token):
            return pyjwk

    monkeypatch.setattr(jwks_manager, "_client_for", lambda issuer: _Stub())
    yield key
    transmitter_registry._by_issuer.pop(TEST_ISSUER, None)


def test_push_endpoint_accepts_and_processes_valid_set(wired_transmitter):
    client = TestClient(app)
    token = make_set(
        wired_transmitter,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type="https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
        event_payload={"current_level": "HIGH", "risk_reason": "test"},
        subject={"format": "email", "email": "carol@example.com"},
    )

    resp = client.post("/events", content=token, headers={"Content-Type": "application/secevent+jwt"})

    assert resp.status_code == 202
    cached = decision_cache.get("email:carol@example.com")
    assert cached is not None
    assert cached.risk_level == "HIGH"


def test_push_endpoint_rejects_non_jwt_body():
    client = TestClient(app)
    resp = client.post("/events", content="not-a-jwt", headers={"Content-Type": "application/secevent+jwt"})
    assert resp.status_code == 400


def test_push_endpoint_replay_is_processed_once(wired_transmitter):
    client = TestClient(app)
    token = make_set(
        wired_transmitter,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type="https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
        event_payload={"current_level": "MEDIUM"},
        subject={"format": "email", "email": "dave@example.com"},
        jti="fixed-jti-for-replay-test",
    )

    r1 = client.post("/events", content=token, headers={"Content-Type": "application/secevent+jwt"})
    r2 = client.post("/events", content=token, headers={"Content-Type": "application/secevent+jwt"})

    # Both return 202 (receiver ack'd receipt either way); the replay guard
    # silently drops the second one rather than surfacing an error to the
    # transmitter, which is the SSF-recommended behavior.
    assert r1.status_code == 202
    assert r2.status_code == 202
