"""SSF Stream Management client: request shape and error reporting.

Motivating case: creating a push stream against a real Keycloak returned a
bare 401 with an empty body, so the 502 said nothing beyond the status code.
The RFC 6750 `WWW-Authenticate` challenge carries the actual reason and must
survive into the error message.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.ssf.registry import TransmitterConfig
from app.ssf.stream_client import (
    PUSH_DELIVERY_METHOD,
    StreamManagementClient,
    StreamManagementError,
)

ISSUER = "https://keycloak.test:30182/realms/demo"
CONFIG_ENDPOINT = f"{ISSUER}/ssf/transmitter/streams"
RECEIVER = "https://bridge.test/events"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"


@pytest.fixture()
def config():
    return TransmitterConfig(
        issuer=ISSUER,
        jwks_uri=f"{ISSUER}/protocol/openid-connect/certs",
        configuration_endpoint=CONFIG_ENDPOINT,
        expected_audience=RECEIVER,
    )


@pytest.fixture()
def client(config):
    return StreamManagementClient(config, "tok-abc")


@respx.mock
@pytest.mark.asyncio
async def test_create_push_stream_sends_rfc8935_delivery_and_bearer(client):
    route = respx.post(CONFIG_ENDPOINT).mock(
        return_value=httpx.Response(201, json={"stream_id": "s-1", "aud": RECEIVER})
    )

    result = await client.create_push_stream(
        receiver_events_endpoint=RECEIVER,
        events_requested=[SESSION_REVOKED],
    )

    assert result["stream_id"] == "s-1"
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer tok-abc"

    import json

    sent = json.loads(req.content)
    assert sent["delivery"]["method"] == PUSH_DELIVERY_METHOD
    assert sent["delivery"]["endpoint_url"] == RECEIVER
    assert sent["events_requested"] == [SESSION_REVOKED]


@respx.mock
@pytest.mark.asyncio
async def test_401_with_empty_body_still_explains_itself(client):
    """Keycloak returns 401 with no body; the status alone is not actionable."""
    respx.post(CONFIG_ENDPOINT).mock(return_value=httpx.Response(401, text=""))

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert CONFIG_ENDPOINT in detail
    assert "401" in detail
    assert "<empty>" in detail
    assert "access_token was rejected" in detail


@respx.mock
@pytest.mark.asyncio
async def test_www_authenticate_challenge_is_surfaced(client):
    """The challenge distinguishes expired vs wrong-audience vs missing scope."""
    respx.post(CONFIG_ENDPOINT).mock(
        return_value=httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'Bearer realm="demo", error="invalid_token", '
                'error_description="Token is not active"'
            },
        )
    )

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert "WWW-Authenticate" in detail
    assert "invalid_token" in detail
    assert "Token is not active" in detail


@respx.mock
@pytest.mark.asyncio
async def test_403_gets_the_same_token_guidance(client):
    respx.post(CONFIG_ENDPOINT).mock(
        return_value=httpx.Response(403, json={"error": "insufficient_scope"})
    )

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert "403" in detail
    assert "insufficient_scope" in detail
    assert "access_token was rejected" in detail


@respx.mock
@pytest.mark.asyncio
async def test_non_auth_error_keeps_the_body_but_omits_token_guidance(client):
    """A 400 is a request-shape problem, not a credentials problem."""
    respx.post(CONFIG_ENDPOINT).mock(
        return_value=httpx.Response(400, json={"error": "unsupported_delivery_method"})
    )

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert "unsupported_delivery_method" in detail
    assert "access_token was rejected" not in detail


@pytest.mark.asyncio
async def test_missing_configuration_endpoint_is_reported_clearly(config):
    config.configuration_endpoint = None
    c = StreamManagementClient(config, "tok")
    with pytest.raises(StreamManagementError, match="no configuration_endpoint"):
        await c.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )
