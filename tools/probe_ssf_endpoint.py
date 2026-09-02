#!/usr/bin/env python3
"""Isolate *why* a transmitter's SSF stream endpoint returns 401.

`stream creation failed: ... 401` has two very different causes and the bridge
cannot tell them apart from the outside:

  A. the token is dead/unknown  -> Keycloak rejects it everywhere
  B. the token is fine, but the SSF endpoint won't authorize it (missing role,
     wrong audience, or the SSF extension isn't really serving that path)

This probes the same token against a known-good Keycloak endpoint (`userinfo`)
first. That single result splits A from B. It then replays the exact POST the
bridge makes and dumps every response header, which is where an empty-bodied
401 hides its reason.

Usage:
    python tools/probe_ssf_endpoint.py \
        --issuer https://keycloak.f5demos.com:30182/realms/geointdemo \
        --access-token "$TOKEN" --insecure

    # add --client-id/--client-secret to also run RFC 7662 introspection
"""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlsplit

import httpx
import jwt

# Must match app/ssf/stream_client.py -- the point of this probe is to replay
# the bridge's exact request, so a divergent delivery method would test the
# wrong thing.
PUSH_DELIVERY_METHOD = "urn:ietf:rfc:8935"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
SSF_SCOPES = ("ssf.read", "ssf.manage")


def show(resp: httpx.Response) -> None:
    print(f"  -> HTTP {resp.status_code}")
    for name in ("www-authenticate", "content-type", "location", "server", "allow"):
        if name in resp.headers:
            print(f"     {name}: {resp.headers[name]}")
    body = resp.text.strip()
    print(f"     body: {body[:300] if body else '<empty>'}")


def step1_token_liveness(client: httpx.Client, issuer: str, token: str, auth: dict) -> None:
    print("=" * 70)
    print("STEP 1: is this token a JWT, and is it live?")
    print("=" * 70)
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        azp = claims.get("azp")
        username = claims.get("preferred_username")
        print(
            f"  JWT. iss={claims.get('iss')} aud={claims.get('aud')!r} "
            f"scope={claims.get('scope')!r}"
        )
        print(f"  azp={azp!r} preferred_username={username!r}")
        granted = set(str(claims.get("scope", "")).split())
        missing = [s for s in SSF_SCOPES if s not in granted]
        if missing:
            print(
                f"\n  >> LIKELY CAUSE: token is missing {' '.join(missing)}.\n"
                "     Keycloak's SSF stream-management API authorizes on\n"
                "     'ssf.read ssf.manage'. Assign them as client scopes and\n"
                "     request them on the client-credentials call."
            )

        # Keycloak's receiver gate (SsfAuthUtil.checkScopePermission step 2)
        # requires, by default, that the caller be the receiver client's *own*
        # service account -- it compares the token user's
        # serviceAccountClientLink against the client's internal id. A
        # client-credentials token from some *other* client carries the right
        # scopes and still gets the identical bare 401, so the identity behind
        # the token matters as much as its scopes.
        if username and not username.startswith("service-account-"):
            print(
                "\n  >> LIKELY CAUSE: this is not a service-account token\n"
                f"     (preferred_username={username!r}). Unless the receiver\n"
                "     client sets ssf.requireServiceAccount=false, Keycloak\n"
                "     requires the client's own service-account token, so a\n"
                "     user login (password / direct-access grant) is refused\n"
                "     regardless of scopes. Use client_credentials."
            )
        elif username and azp and username != f"service-account-{azp}":
            print(
                "\n  >> LIKELY CAUSE: service-account/client mismatch.\n"
                f"     username={username!r} but azp={azp!r}. Keycloak checks\n"
                "     the token belongs to the receiver client's OWN service\n"
                "     account; another client's token is refused."
            )
        elif azp:
            print(
                f"\n  NOTE: ssf.enabled=true must be set on client {azp!r}\n"
                "     (the azp above) -- that is the client Keycloak gates on,\n"
                "     not whichever client you configured in the admin UI."
            )
    except Exception:
        print("  opaque (not a JWT) -- the SSF endpoint must use introspection")

    print("\n  probing userinfo with the same token ...")
    ui = client.get(f"{issuer}/protocol/openid-connect/userinfo", headers=auth)
    show(ui)
    if ui.status_code == 401:
        print("\n  >> VERDICT: the token itself is rejected by Keycloak.")
        print("     Mint a fresh one (tools/get_keycloak_token.py). Not an SSF issue.")
    elif ui.status_code == 403:
        print("\n  >> authentic but lacks userinfo scope -- inconclusive, continuing")
    elif ui.status_code == 200:
        print("\n  >> VERDICT: the token is VALID and ACTIVE.")
        print("     A 401 from the SSF endpoint is therefore NOT about token validity;")
        print("     it is authorization (role/audience) or the endpoint isn't SSF.")


def step2_introspect(client: httpx.Client, issuer: str, token: str, cid: str, secret: str) -> None:
    print("\n" + "=" * 70)
    print("STEP 2: RFC 7662 introspection (authoritative)")
    print("=" * 70)
    intro = client.post(
        f"{issuer}/protocol/openid-connect/token/introspect",
        data={"token": token, "client_id": cid, "client_secret": secret},
    )
    if intro.status_code != 200:
        show(intro)
        return
    data = intro.json()
    print(f"  active={data.get('active')}")
    for k in ("aud", "scope", "azp", "exp", "realm_access", "resource_access"):
        if k in data:
            print(f"  {k}: {json.dumps(data[k])}")
    if data.get("active") is False:
        print("  >> token is INACTIVE (expired or revoked)")


def step3_metadata(client: httpx.Client, issuer: str, auth: dict) -> dict:
    print("\n" + "=" * 70)
    print("STEP 3: what does the SSF metadata advertise?")
    print("=" * 70)
    parts = urlsplit(issuer)
    meta_url = f"{parts.scheme}://{parts.netloc}/.well-known/ssf-configuration{parts.path}"
    print(f"  GET {meta_url}")
    resp = client.get(meta_url, headers=auth)
    if resp.status_code != 200:
        show(resp)
        sys.exit(1)
    meta = resp.json()
    for k, v in meta.items():
        print(f"     {k}: {v if isinstance(v, str) else json.dumps(v)}")

    supported = meta.get("delivery_methods_supported") or []
    if supported and PUSH_DELIVERY_METHOD not in supported:
        print(
            f"\n  !! the bridge sends delivery method {PUSH_DELIVERY_METHOD!r},\n"
            "     which is NOT in delivery_methods_supported. Keycloak also\n"
            "     accepts the legacy RISC URI\n"
            "     'https://schemas.openid.net/secevent/risc/delivery-method/push'."
        )

    config_endpoint = meta.get("configuration_endpoint", "")
    if config_endpoint and "/ssf/transmitter/streams" not in config_endpoint:
        print(
            "\n  !! configuration_endpoint does not end in /ssf/transmitter/streams,\n"
            "     which is the path Keycloak's SSF extension serves. A different\n"
            "     path suggests a non-Keycloak transmitter or a rewriting proxy."
        )
    return meta


def step4_replay(client: httpx.Client, config_endpoint: str, receiver: str, auth: dict) -> None:
    print("\n" + "=" * 70)
    print("STEP 4: replay the bridge's exact POST")
    print("=" * 70)
    payload = {
        "delivery": {"method": PUSH_DELIVERY_METHOD, "endpoint_url": receiver},
        "events_requested": [SESSION_REVOKED],
        "description": "ssf-apm-bridge probe",
    }
    json_auth = {**auth, "Content-Type": "application/json"}

    print(f"  POST {config_endpoint}")
    p = client.post(config_endpoint, json=payload, headers=json_auth)
    show(p)

    print("\n  same URL, GET (does it exist at all?)")
    g = client.get(config_endpoint, headers=auth)
    show(g)
    if g.status_code == 404:
        print("     >> 404 on GET: the SSF extension may not be serving this path.")

    # GET /streams is gated on ssf.read, POST on ssf.manage, but every other
    # check (valid token, ssf.enabled, service-account, required role) is
    # shared. Comparing the two therefore isolates which gate is failing --
    # something the identical bare 401s cannot do on their own.
    if g.status_code in (200, 204) and p.status_code == 401:
        print(
            "\n     >> VERDICT: GET passed but POST 401'd. Every shared gate\n"
            "        (token, ssf.enabled, service-account, required role) is\n"
            "        therefore satisfied and only the 'ssf.manage' scope is\n"
            "        missing. Re-mint with scope='ssf.read ssf.manage'."
        )
    elif g.status_code == 401 and p.status_code == 401:
        print(
            "\n     >> VERDICT: GET *and* POST both 401. The failure is in a\n"
            "        gate shared by both, NOT the ssf.manage scope: the token\n"
            "        is invalid/expired, or the client behind it lacks\n"
            "        ssf.enabled=true, or is not its own service account, or\n"
            "        misses ssf.requiredRole, or has no ssf.read either."
        )

    print("\n  same URL, POST with NO token (compare the challenge)")
    show(client.post(config_endpoint, json=payload,
                     headers={"Content-Type": "application/json"}))
    print("     If the no-token 401 looks identical to the with-token 401, that")
    print("     is EXPECTED here: Keycloak returns a bare 401 for every SSF")
    print("     authorization failure. Only conclude the header was stripped if")
    print("     STEP 1's userinfo call also failed with the same token.")


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--issuer", required=True)
    p.add_argument("--access-token", required=True)
    p.add_argument("--client-id")
    p.add_argument("--client-secret")
    p.add_argument("--receiver", default="https://ssf-bridge.example.com/events")
    p.add_argument("--insecure", action="store_true")
    args = p.parse_args()

    issuer = args.issuer.rstrip("/")
    auth = {"Authorization": f"Bearer {args.access_token}"}
    client = httpx.Client(timeout=15.0, verify=not args.insecure, follow_redirects=True)
    try:
        step1_token_liveness(client, issuer, args.access_token, auth)
        if args.client_id and args.client_secret:
            step2_introspect(client, issuer, args.access_token,
                             args.client_id, args.client_secret)
        meta = step3_metadata(client, issuer, auth)
        config_endpoint = meta.get("configuration_endpoint")
        if not config_endpoint:
            print("\n  !! no configuration_endpoint advertised -- cannot create a stream")
            sys.exit(1)
        step4_replay(client, config_endpoint, args.receiver, auth)
    finally:
        client.close()


if __name__ == "__main__":
    main()
