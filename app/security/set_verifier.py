"""SET verification: signature, typing, and claim shape.

This is the trust boundary of the whole bridge -- everything downstream
(session termination included) acts on what this module hands back, so it
fails closed: any check that doesn't pass raises rather than degrading.
"""
from __future__ import annotations

import jwt
from jwt.exceptions import InvalidTokenError

from app.models import SecurityEventToken
from app.security.jwks import jwks_manager
from app.ssf.registry import TransmitterRegistry, UnknownIssuer

ALLOWED_ALGORITHMS = ["RS256", "PS256", "ES256"]


class SetVerificationError(Exception):
    pass


def verify_set(token: str, registry: TransmitterRegistry) -> SecurityEventToken:
    # 1. Peek claims without trusting them yet, just to find the issuer so
    #    we know which transmitter's key set to check against.
    try:
        header = jwt.get_unverified_header(token)
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
    except InvalidTokenError as exc:
        raise SetVerificationError(f"malformed JWT: {exc}") from exc

    typ = header.get("typ", "")
    if typ.lower() not in ("secevent+jwt", "application/secevent+jwt"):
        raise SetVerificationError(f"unexpected typ header {typ!r}, expected secevent+jwt")

    issuer = unverified_claims.get("iss")
    if not issuer:
        raise SetVerificationError("SET is missing 'iss'")

    try:
        transmitter = registry.get(issuer)
    except UnknownIssuer as exc:
        raise SetVerificationError(str(exc)) from exc

    # 2. Now verify the signature for real, against that issuer's JWKS.
    try:
        signing_key = jwks_manager.signing_key_for(issuer, token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=transmitter.expected_audience,
            options={
                "require": ["iss", "iat", "jti", "aud"],
                "verify_exp": False,  # SETs deliberately omit exp per the SSF spec
            },
        )
    except InvalidTokenError as exc:
        raise SetVerificationError(f"signature/claims verification failed: {exc}") from exc

    if "sub" in claims:
        # Not fatal (some transmitters are sloppy about this), but a SET
        # shouldn't carry a top-level `sub` -- subject lives in `sub_id`.
        claims = {k: v for k, v in claims.items() if k != "sub"}

    if "sub_id" not in claims:
        raise SetVerificationError("SET is missing 'sub_id'")
    if "events" not in claims or not claims["events"]:
        raise SetVerificationError("SET is missing a non-empty 'events' claim")

    return SecurityEventToken.model_validate(claims)
