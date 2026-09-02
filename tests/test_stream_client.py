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
    POLL_DELIVERY_METHOD,
    PUSH_DELIVERY_METHOD,
    SSF_TOKEN_SCOPES,
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


def test_delivery_methods_match_the_rfc_urn_forms():
    """Keycloak accepts four delivery URIs and collapses them into the
    `push` / `poll` families; the RFC 8935 / 8936 URNs are the modern spelling
    and are what `delivery_methods_supported` advertises first."""
    assert PUSH_DELIVERY_METHOD == "urn:ietf:rfc:8935"
    assert POLL_DELIVERY_METHOD == "urn:ietf:rfc:8936"


def test_ssf_token_scopes_match_keycloak():
    """Keycloak's stream-management API authorizes on these two scopes; a
    token without them authenticates but is refused, which is the single most
    common cause of the bare 401 this module reports."""
    assert SSF_TOKEN_SCOPES == "ssf.read ssf.manage"


@respx.mock
@pytest.mark.asyncio
async def test_401_names_the_scopes_keycloak_requires(client):
    """The empty-bodied 401 gives the operator nothing to act on, so the
    error has to name the scopes and the client attribute itself."""
    respx.post(CONFIG_ENDPOINT).mock(return_value=httpx.Response(401, text=""))

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert "ssf.read ssf.manage" in detail
    assert "ssf.enabled=true" in detail


@respx.mock
@pytest.mark.asyncio
async def test_401_covers_every_keycloak_receiver_gate(client):
    """Keycloak's SsfAuthUtil.checkScopePermission rejects with the same bare
    401 for five different reasons, and a missing scope is only one of them.
    The service-account identity check is the one that catches operators who
    already added `ssf.read ssf.manage`: Keycloak requires the receiver
    client's *own* service-account token, so another client's
    client-credentials token is refused with the right scopes. All the gates
    must be named or the operator fixes the scopes and stalls."""
    respx.post(CONFIG_ENDPOINT).mock(return_value=httpx.Response(401, text=""))

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert "ssf.requireServiceAccount" in detail
    assert "ssf.requiredRole" in detail
    # The absent challenge is itself misleading here, so say so explicitly.
    assert "WWW-Authenticate" in detail


@respx.mock
@pytest.mark.asyncio
async def test_401_without_a_challenge_does_not_claim_one_is_expected(client):
    """Keycloak's SSF gate returns `Response.status(UNAUTHORIZED).build()` --
    no RFC 6750 challenge, ever. So a missing `WWW-Authenticate` must not be
    read as "the request never reached bearer evaluation"; that inference sent
    us looking at the feature flag and the proxy instead of the token."""
    respx.post(CONFIG_ENDPOINT).mock(return_value=httpx.Response(401, text=""))

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    assert "an absent challenge here says nothing" in str(exc.value)


@respx.mock
@pytest.mark.asyncio
async def test_409_explains_keycloaks_one_stream_per_receiver_limit(client):
    """Keycloak permits exactly one stream per receiver client, so a retry
    after a partial failure 409s instead of replacing the stream."""
    respx.post(CONFIG_ENDPOINT).mock(return_value=httpx.Response(409, text=""))

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert "409" in detail
    assert "already exists" in detail
    assert "access_token was rejected" not in detail


@respx.mock
@pytest.mark.asyncio
async def test_400_points_at_the_push_url_allow_list(client):
    """Keycloak's SSRF gate rejects a push URL that isn't in the receiver's
    ssf.validPushUrls allow-list with a deliberately generic 400."""
    respx.post(CONFIG_ENDPOINT).mock(
        return_value=httpx.Response(400, json={"error": "invalid_request"})
    )

    with pytest.raises(StreamManagementError) as exc:
        await client.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )

    detail = str(exc.value)
    assert "ssf.validPushUrls" in detail
    assert "ssf.allowedDeliveryMethods" in detail


@pytest.mark.asyncio
async def test_missing_configuration_endpoint_is_reported_clearly(config):
    config.configuration_endpoint = None
    c = StreamManagementClient(config, "tok")
    with pytest.raises(StreamManagementError, match="no configuration_endpoint"):
        await c.create_push_stream(
            receiver_events_endpoint=RECEIVER, events_requested=[SESSION_REVOKED]
        )
