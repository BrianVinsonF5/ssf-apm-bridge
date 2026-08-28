"""Helpers to mint self-signed SETs for tests, so the suite doesn't depend
on a real transmitter anywhere."""
from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def generate_rsa_keypair() -> RSAPrivateKey:
    return generate_private_key(public_exponent=65537, key_size=2048)


def jwk_public(private_key: RSAPrivateKey, kid: str) -> dict:
    pub = private_key.public_key().public_numbers()

    def _b64url_uint(n: int) -> str:
        import base64

        byte_len = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(byte_len, "big")).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(pub.n),
        "e": _b64url_uint(pub.e),
    }


def make_set(
    private_key: RSAPrivateKey,
    *,
    kid: str,
    issuer: str,
    audience: str,
    event_type: str | None = None,
    event_payload: dict[str, Any] | None = None,
    events: dict[str, dict[str, Any]] | None = None,
    subject: dict[str, Any] | None = None,
    jti: str | None = None,
    iat: int | None = None,
) -> str:
    """Mint a signed SET.

    Pass either `event_type`/`event_payload` for the common single-event case,
    or `events` to build a multi-event SET (RFC 8417 allows several events in
    one token). `iat` can be overridden to exercise freshness checks.
    """
    if events is None:
        if event_type is None:
            raise ValueError("pass either event_type or events")
        events = {event_type: event_payload or {}}

    claims = {
        "iss": issuer,
        "iat": int(time.time()) if iat is None else iat,
        "jti": jti or str(uuid.uuid4()),
        "aud": audience,
        "sub_id": subject or {"format": "email", "email": "alice@example.com"},
        "events": events,
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"typ": "secevent+jwt", "kid": kid})
