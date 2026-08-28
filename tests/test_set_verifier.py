from __future__ import annotations

import time

import pytest
from jwt.exceptions import PyJWKClientError

from app.config import settings
from app.security.jwks import IssuerNotRegistered, jwks_manager
from app.security.set_verifier import SetVerificationError, verify_set
from tests.conftest import TEST_AUDIENCE, TEST_ISSUER, TEST_KID
from tests.fixtures.sample_sets import make_set

SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"


def test_verify_valid_set(rsa_keypair, transmitter_registry, register_signing_key):
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type="https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        event_payload={"event_timestamp": 1700000000},
    )

    set_ = verify_set(token, transmitter_registry)

    assert set_.iss == TEST_ISSUER
    assert set_.primary_event_type() == "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    assert set_.sub_id.correlation_key() == "email:alice@example.com"


def test_rejects_unknown_issuer(rsa_keypair, transmitter_registry, register_signing_key):
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer="https://someone-else.test",
        audience=TEST_AUDIENCE,
        event_type="https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        event_payload={},
    )

    with pytest.raises(SetVerificationError, match="no transmitter registered"):
        verify_set(token, transmitter_registry)


def test_rejects_wrong_audience(rsa_keypair, transmitter_registry, register_signing_key):
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience="https://not-us.example",
        event_type="https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        event_payload={},
    )

    with pytest.raises(SetVerificationError, match="verification failed"):
        verify_set(token, transmitter_registry)


def test_rejects_tampered_signature(rsa_keypair, transmitter_registry, register_signing_key):
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type="https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        event_payload={},
    )
    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]

    with pytest.raises(SetVerificationError):
        verify_set(tampered, transmitter_registry)


def test_rejects_wrong_typ_header(rsa_keypair, transmitter_registry, register_signing_key):
    import jwt as pyjwt

    claims = {
        "iss": TEST_ISSUER,
        "iat": 1700000000,
        "jti": "abc",
        "aud": TEST_AUDIENCE,
        "sub_id": {"format": "email", "email": "alice@example.com"},
        "events": {"https://schemas.openid.net/secevent/caep/event-type/session-revoked": {}},
    }
    token = pyjwt.encode(claims, rsa_keypair, algorithm="RS256", headers={"typ": "JWT", "kid": TEST_KID})

    with pytest.raises(SetVerificationError, match="secevent"):
        verify_set(token, transmitter_registry)


def test_rejects_missing_events(rsa_keypair, transmitter_registry, register_signing_key):
    import jwt as pyjwt

    claims = {
        "iss": TEST_ISSUER,
        "iat": int(time.time()),
        "jti": "abc",
        "aud": TEST_AUDIENCE,
        "sub_id": {"format": "email", "email": "alice@example.com"},
    }
    token = pyjwt.encode(claims, rsa_keypair, algorithm="RS256", headers={"typ": "secevent+jwt", "kid": TEST_KID})

    with pytest.raises(SetVerificationError, match="events"):
        verify_set(token, transmitter_registry)


# --- freshness (SETs carry no `exp`, so `iat` age is the only bound) --------


def test_rejects_stale_set(rsa_keypair, transmitter_registry, register_signing_key):
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type=SESSION_REVOKED,
        event_payload={},
        iat=int(time.time()) - (settings.set_max_age_seconds + 60),
    )

    with pytest.raises(SetVerificationError, match="stale"):
        verify_set(token, transmitter_registry)


def test_rejects_set_dated_too_far_in_the_future(rsa_keypair, transmitter_registry, register_signing_key):
    """Beyond the configured skew, PyJWT's own iat check fires and is
    translated into SetVerificationError."""
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type=SESSION_REVOKED,
        event_payload={},
        iat=int(time.time()) + settings.set_clock_skew_seconds + 60,
    )

    with pytest.raises(SetVerificationError, match="not yet valid"):
        verify_set(token, transmitter_registry)


def test_accepts_set_within_allowed_clock_skew(rsa_keypair, transmitter_registry, register_signing_key):
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type=SESSION_REVOKED,
        event_payload={},
        iat=int(time.time()) + 5,
    )

    assert verify_set(token, transmitter_registry).iss == TEST_ISSUER


# --- JWKS-layer failures must surface as SetVerificationError ---------------
# Regression: these exceptions do not derive from InvalidTokenError, so they
# used to escape verify_set entirely and kill the caller's background task
# after the transmitter had already been ACKed -- silently losing the event.


def test_unreachable_jwks_raises_set_verification_error(
    rsa_keypair, transmitter_registry, register_signing_key, monkeypatch
):
    def boom(issuer, token):
        raise PyJWKClientError("Unable to find a signing key")

    monkeypatch.setattr(jwks_manager, "signing_key_for", boom)
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type=SESSION_REVOKED,
        event_payload={},
    )

    with pytest.raises(SetVerificationError, match="could not resolve signing key"):
        verify_set(token, transmitter_registry)


def test_unregistered_issuer_in_jwks_manager_raises_set_verification_error(
    rsa_keypair, transmitter_registry, register_signing_key, monkeypatch
):
    """The transmitter registry and the JWKS manager are separate stores and
    can drift apart; that must not be an unhandled crash."""

    def boom(issuer, token):
        raise IssuerNotRegistered(f"no jwks_uri registered for issuer {issuer!r}")

    monkeypatch.setattr(jwks_manager, "signing_key_for", boom)
    token = make_set(
        rsa_keypair,
        kid=TEST_KID,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        event_type=SESSION_REVOKED,
        event_payload={},
    )

    with pytest.raises(SetVerificationError, match="could not resolve signing key"):
        verify_set(token, transmitter_registry)
