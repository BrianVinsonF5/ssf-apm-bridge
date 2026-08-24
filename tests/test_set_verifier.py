from __future__ import annotations

import pytest

from app.security.set_verifier import SetVerificationError, verify_set
from tests.conftest import TEST_AUDIENCE, TEST_ISSUER, TEST_KID
from tests.fixtures.sample_sets import make_set


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
        "iat": 1700000000,
        "jti": "abc",
        "aud": TEST_AUDIENCE,
        "sub_id": {"format": "email", "email": "alice@example.com"},
    }
    token = pyjwt.encode(claims, rsa_keypair, algorithm="RS256", headers={"typ": "secevent+jwt", "kid": TEST_KID})

    with pytest.raises(SetVerificationError, match="events"):
        verify_set(token, transmitter_registry)
