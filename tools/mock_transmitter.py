#!/usr/bin/env python3
"""End-to-end demo with zero external dependencies.

Runs a throwaway JWKS server on localhost, registers itself with a running
bridge as a transmitter, registers a fake APM session (standing in for
what BIG-IP's ACCESS_SESSION_STARTED iRule would do), then pushes a
handful of signed CAEP/RISC SETs and shows what the bridge did with each.

Usage:
    # terminal 1
    uvicorn app.main:app --port 8080

    # terminal 2
    export ADMIN_API_KEY=...   # must match the bridge's .env
    python tools/mock_transmitter.py
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

DEMO_SUBJECT = {"format": "email", "email": "demo.user@example.com"}
DEMO_APM_SESSION_ID = "".join("abcdef0123456789"[i % 16] for i in range(24))
KID = "demo-key-1"


def b64url_uint(n: int) -> str:
    byte_len = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(byte_len, "big")).rstrip(b"=").decode()


def make_jwks(private_key) -> dict:
    pub = private_key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": b64url_uint(pub.n),
                "e": b64url_uint(pub.e),
            }
        ]
    }


def start_jwks_server(private_key, port: int) -> str:
    jwks_body = json.dumps(make_jwks(private_key)).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/.well-known/jwks.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(jwks_body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):  # silence
            pass

    # Bind and advertise 127.0.0.1 rather than "localhost": on Windows
    # "localhost" resolves to ::1 first, so the bridge's urllib-based JWKS
    # fetch would hit a closed IPv6 port and every SET would fail
    # verification with a connection error.
    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}"


def sign_set(private_key, *, issuer: str, audience: str, event_type: str, payload: dict, subject: dict = DEMO_SUBJECT) -> str:
    claims = {
        "iss": issuer,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "aud": audience,
        "sub_id": subject,
        "events": {event_type: payload},
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"typ": "secevent+jwt", "kid": KID})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bridge-url", default=os.environ.get("BRIDGE_URL", "http://localhost:8080"))
    parser.add_argument("--admin-api-key", default=os.environ.get("ADMIN_API_KEY"))
    parser.add_argument("--jwks-port", type=int, default=9100)
    args = parser.parse_args()

    if not args.admin_api_key:
        sys.exit("Set ADMIN_API_KEY (must match the bridge's .env) or pass --admin-api-key")

    headers = {"X-API-Key": args.admin_api_key}
    http = httpx.Client(timeout=10.0)

    print("== generating throwaway signing key ==")
    key = generate_private_key(public_exponent=65537, key_size=2048)

    print(f"== starting local JWKS server on :{args.jwks_port} ==")
    issuer = start_jwks_server(key, args.jwks_port)
    jwks_uri = f"{issuer}/.well-known/jwks.json"
    audience = f"{args.bridge_url}/events"

    print(f"== registering transmitter (issuer={issuer}) with bridge ==")
    resp = http.post(
        f"{args.bridge_url}/admin/transmitters",
        headers=headers,
        json={"issuer": issuer, "jwks_uri": jwks_uri, "expected_audience": audience},
    )
    resp.raise_for_status()
    print(resp.json())

    print(f"== registering a fake APM session for {DEMO_SUBJECT['email']} ==")
    resp = http.post(
        f"{args.bridge_url}/correlation/sessions",
        headers=headers,
        json={**DEMO_SUBJECT, "apm_session_id": DEMO_APM_SESSION_ID, "apm_username": "demo.user"},
    )
    resp.raise_for_status()
    print(resp.json())

    scenarios = [
        (
            "CONTINUOUS -- risk-level-change (HIGH)",
            "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
            {"current_level": "HIGH", "previous_level": "LOW", "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH"},
        ),
        (
            "CONTINUOUS -- device-compliance-change (not-compliant)",
            "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
            {"current_status": "not-compliant", "previous_status": "compliant", "reason_user": {"en": "Device is no longer in a trusted location."}},
        ),
        (
            "FAST -- session-revoked",
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
            {"event_timestamp": int(time.time()), "reason_admin": {"en": "Landspeed Policy Violation"}},
        ),
        (
            "INFORMATIONAL -- unrecognized event type",
            "https://schemas.openid.net/secevent/caep/event-type/does-not-exist-yet",
            {},
        ),
    ]

    for label, event_type, payload in scenarios:
        print(f"\n== sending SET: {label} ==")
        token = sign_set(key, issuer=issuer, audience=audience, event_type=event_type, payload=payload)
        resp = http.post(f"{args.bridge_url}/events", content=token, headers={"Content-Type": "application/secevent+jwt"})
        print(f"  -> HTTP {resp.status_code}")
        time.sleep(0.3)  # let the background task finish before we check state

    print("\n== decision cache for demo.user@example.com after all events ==")
    # The bridge acks with 202 *before* processing, and the very first
    # verification pays for the JWKS fetch, so poll instead of assuming the
    # background tasks have already landed.
    for _ in range(20):
        resp = http.get(
            f"{args.bridge_url}/internal/decision",
            headers=headers,
            params={"subject_key": "email:demo.user@example.com"},
        )
        if resp.status_code == 200:
            break
        time.sleep(0.5)
    print(f"  HTTP {resp.status_code}: {resp.json() if resp.status_code == 200 else resp.text}")

    print(
        "\nDone. Check the bridge's own log output for 'event_processed' lines -- "
        "the session-revoked event should show fast_path_disabled unless you set "
        "BIGIP_ENABLE_FAST_PATH=true against a real box."
    )


if __name__ == "__main__":
    main()
