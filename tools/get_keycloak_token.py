#!/usr/bin/env python3
"""Mint an access_token from Keycloak for a transmitter's SSF API, and check it.

The `access_token` that `POST /admin/transmitters/discover` wants is issued by
the *transmitter* (Keycloak), not by this bridge -- it is unrelated to
ADMIN_API_KEY. This mints one via the client-credentials grant and then reports
the properties that actually cause a 401 at the SSF stream endpoint: lifetime,
audience, scopes, and whether the token is a JWT at all.

Usage:
    python tools/get_keycloak_token.py \
        --issuer https://keycloak.f5demos.com:30182/realms/geointdemo \
        --client-id ssf-bridge --client-secret <secret> --insecure

    # print only the raw token, for scripting:
    python tools/get_keycloak_token.py ... --quiet | clip
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import httpx
import jwt


def decode_unverified(token: str) -> dict | None:
    """Best-effort claim decode. Returns None for opaque (non-JWT) tokens."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None


def describe(token: str, requested_scope: str | None) -> None:
    claims = decode_unverified(token)
    if claims is None:
        print(
            "\n!! This is an OPAQUE token, not a JWT.\n"
            "   Keycloak issues these when the client's access token signature\n"
            "   algorithm is set to none, or when a token-exchange/lightweight\n"
            "   profile is in play. An SSF endpoint that validates JWTs locally\n"
            "   will reject it unless introspection is enabled."
        )
        return

    now = int(time.time())
    exp = claims.get("exp")
    aud = claims.get("aud")
    scope = claims.get("scope", "")

    print("\n== token claims ==")
    print(f"  iss  : {claims.get('iss')}")
    print(f"  aud  : {aud!r}")
    print(f"  azp  : {claims.get('azp')}")
    print(f"  scope: {scope!r}")
    print(f"  typ  : {claims.get('typ')}")

    if exp:
        remaining = exp - now
        if remaining <= 0:
            print(f"  !! ALREADY EXPIRED {abs(remaining)}s ago")
        else:
            print(f"  exp  : in {remaining}s ({remaining // 60}m)")
            if remaining < 120:
                print(
                    "  !! Short lifetime -- mint it immediately before calling\n"
                    "     /admin/transmitters/discover, or raise the client's\n"
                    "     Access Token Lifespan in Keycloak."
                )

    if requested_scope:
        granted = set(scope.split())
        missing = [s for s in requested_scope.split() if s not in granted]
        if missing:
            print(
                f"  !! Requested scope(s) NOT granted: {' '.join(missing)}\n"
                "     Keycloak silently drops scopes a client is not allowed to\n"
                "     request. Add it as an assigned (default/optional) client\n"
                "     scope in the realm."
            )

    if aud in ("account", ["account"]):
        print(
            "  !! aud is only 'account' -- the realm's default. The SSF endpoint\n"
            "     probably expects its own audience; add an Audience mapper to a\n"
            "     client scope assigned to this client."
        )


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--issuer", required=True, help="realm URL, e.g. https://kc/realms/demo")
    p.add_argument("--client-id", required=True)
    p.add_argument("--client-secret", required=True)
    p.add_argument("--scope", default=None, help="space-separated scopes to request")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    p.add_argument("--quiet", action="store_true", help="print only the token")
    args = p.parse_args()

    token_url = f"{args.issuer.rstrip('/')}/protocol/openid-connect/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": args.client_id,
        "client_secret": args.client_secret,
    }
    if args.scope:
        data["scope"] = args.scope

    if not args.quiet:
        print(f"== POST {token_url} ==")

    try:
        resp = httpx.post(
            token_url, data=data, timeout=15.0, verify=not args.insecure, follow_redirects=True
        )
    except httpx.HTTPError as exc:
        print(f"request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if resp.status_code != 200:
        print(f"HTTP {resp.status_code}: {resp.text[:600]}", file=sys.stderr)
        if resp.status_code == 401:
            print(
                "\nunauthorized_client / invalid_client usually means the client is\n"
                "public rather than confidential, or 'Service accounts roles' is off.",
                file=sys.stderr,
            )
        raise SystemExit(1)

    payload = resp.json()
    token = payload.get("access_token", "")

    if args.quiet:
        print(token)
        return

    print(f"  HTTP 200, expires_in={payload.get('expires_in')}s")
    describe(token, args.scope)

    print("\n== access_token ==")
    print(token)
    print("\n== paste into /admin/transmitters/discover ==")
    print(
        json.dumps(
            {
                "issuer_or_config_url": args.issuer,
                "access_token": token,
                "events_requested": [
                    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
                ],
                **({"verify_tls": False} if args.insecure else {}),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
