"""SET verification: signature, typing, and claim shape.

This is the trust boundary of the whole bridge -- everything downstream
(session termination included) acts on what this module hands back, so it
fails closed: any check that doesn't pass raises rather than degrading.
"""
from __future__ import annotations

import time

import jwt
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from app.config import settings
from app.models import SecurityEventToken
from app.security.jwks import IssuerNotRegistered, jwks_manager
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
    #    Key resolution is a *network* operation and raises its own
    #    exception family (PyJWKClientError on an unreachable JWKS or an
    #    unresolvable kid, IssuerNotRegistered if the registry and the JWKS
    #    manager have drifted apart). Neither derives from InvalidTokenError,
    #    so both are translated here -- otherwise they escape this function
    #    entirely and kill the caller's background task after the transmitter
    #    has already been ACKed, silently losing the event.
    try:
        signing_key = jwks_manager.signing_key_for(issuer, token)
    except (PyJWKClientError, IssuerNotRegistered) as exc:
        raise SetVerificationError(f"could not resolve signing key for issuer {issuer!r}: {exc}") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=transmitter.expected_audience,
            # PyJWT enforces "iat must not be in the future" using this
            # leeway, so transmitter/receiver clock drift is tolerated here
            # rather than rejected outright.
            leeway=settings.set_clock_skew_seconds,
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

    # SETs carry no `exp` by design, so `iat` age is the only thing bounding
    # how long a captured token stays useful. Without this, a SET replayed
    # after its jti falls out of the replay guard's window is accepted and
    # fully re-enforced.
    _reject_stale_iat(claims["iat"])

    return SecurityEventToken.model_validate(claims)


def _reject_stale_iat(iat: object) -> None:
    """Reject SETs that are too old to act on.

    Only the *upper* age bound lives here: future-dated `iat` is already
    rejected by jwt.decode above, using set_clock_skew_seconds as leeway.
    """
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        raise SetVerificationError(f"SET 'iat' must be a numeric timestamp, got {iat!r}")

    age = time.time() - float(iat)
    if age > settings.set_max_age_seconds:
        raise SetVerificationError(
            f"SET is stale: iat is {int(age)}s old, limit is {settings.set_max_age_seconds}s"
        )
