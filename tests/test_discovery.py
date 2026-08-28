"""SSF transmitter discovery: well-known URL construction and the error
reporting around it.

The regression that motivated most of these: a transport-level failure
surfaced as a bare 502 with detail "discovery failed: Server disconnected
without sending a response." -- no URL, no exception class, nothing in the
pod log. Every failure path here asserts the URL makes it into the message.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.security.jwks import (
    SSF_CONFIGURATION_SEGMENT,
    SsfDiscoveryError,
    fetch_ssf_configuration,
    ssf_configuration_urls,
)

METADATA = {
    "issuer": "https://idp.test",
    "jwks_uri": "https://idp.test/.well-known/jwks.json",
    "configuration_endpoint": "https://idp.test/ssf/stream",
}


# --- URL construction -------------------------------------------------


def test_pathless_issuer_yields_a_single_url():
    assert ssf_configuration_urls("https://idp.test") == [
        f"https://idp.test{SSF_CONFIGURATION_SEGMENT}"
    ]


def test_trailing_slash_does_not_double_up():
    assert ssf_configuration_urls("https://idp.test/") == [
        f"https://idp.test{SSF_CONFIGURATION_SEGMENT}"
    ]


def test_issuer_with_path_yields_rfc8414_form_first_then_appended():
    """Keycloak-style issuer. RFC 8414 inserts the well-known segment
    between authority and path; the legacy form appends it. Both are served
    in the wild, so we try the spec form first and fall back."""
    assert ssf_configuration_urls("https://kc.test/realms/corp") == [
        "https://kc.test/.well-known/ssf-configuration/realms/corp",
        "https://kc.test/realms/corp/.well-known/ssf-configuration",
    ]


def test_full_metadata_url_is_used_verbatim():
    url = "https://idp.test/.well-known/ssf-configuration"
    assert ssf_configuration_urls(url) == [url]


def test_full_metadata_url_with_trailing_slash_is_not_rewritten():
    url = "https://idp.test/.well-known/ssf-configuration/"
    assert ssf_configuration_urls(url) == [url]


# --- happy path -------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetches_metadata_from_pathless_issuer():
    route = respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(200, json=METADATA)
    )

    assert await fetch_ssf_configuration("https://idp.test") == METADATA
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_falls_back_to_appended_form_when_rfc8414_form_404s():
    rfc_route = respx.get("https://kc.test/.well-known/ssf-configuration/realms/corp").mock(
        return_value=httpx.Response(404, text="not found")
    )
    appended_route = respx.get("https://kc.test/realms/corp/.well-known/ssf-configuration").mock(
        return_value=httpx.Response(200, json=METADATA)
    )

    assert await fetch_ssf_configuration("https://kc.test/realms/corp") == METADATA
    assert rfc_route.called
    assert appended_route.called


@respx.mock
@pytest.mark.asyncio
async def test_access_token_is_sent_as_bearer_when_supplied():
    """SSF 1.0 s7.1.1 allows a protected Transmitter Configuration endpoint."""
    route = respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(200, json=METADATA)
    )

    await fetch_ssf_configuration("https://idp.test", access_token="tok-abc")

    assert route.calls.last.request.headers["authorization"] == "Bearer tok-abc"


@respx.mock
@pytest.mark.asyncio
async def test_no_authorization_header_when_no_token():
    route = respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(200, json=METADATA)
    )

    await fetch_ssf_configuration("https://idp.test")

    assert "authorization" not in route.calls.last.request.headers


@respx.mock
@pytest.mark.asyncio
async def test_follows_redirects():
    """An IdP that 302s to the canonical URL used to leave us calling
    .json() on an empty redirect body."""
    respx.get(f"http://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(
            302, headers={"Location": f"https://idp.test{SSF_CONFIGURATION_SEGMENT}"}
        )
    )
    final = respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(200, json=METADATA)
    )

    assert await fetch_ssf_configuration("http://idp.test") == METADATA
    assert final.called


# --- failure reporting ------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_transport_error_message_names_the_url_and_exception_class():
    """The reported bug: the httpx message alone identifies neither the URL
    nor the failure mode."""
    respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        side_effect=httpx.RemoteProtocolError("Server disconnected without sending a response.")
    )

    with pytest.raises(SsfDiscoveryError) as exc:
        await fetch_ssf_configuration("https://idp.test")

    detail = str(exc.value)
    assert f"https://idp.test{SSF_CONFIGURATION_SEGMENT}" in detail
    assert "RemoteProtocolError" in detail
    assert "Server disconnected" in detail


@respx.mock
@pytest.mark.asyncio
async def test_error_lists_every_candidate_url_tried():
    respx.get("https://kc.test/.well-known/ssf-configuration/realms/corp").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    respx.get("https://kc.test/realms/corp/.well-known/ssf-configuration").mock(
        return_value=httpx.Response(503, text="unavailable")
    )

    with pytest.raises(SsfDiscoveryError) as exc:
        await fetch_ssf_configuration("https://kc.test/realms/corp")

    detail = str(exc.value)
    assert "https://kc.test/.well-known/ssf-configuration/realms/corp" in detail
    assert "https://kc.test/realms/corp/.well-known/ssf-configuration" in detail
    assert "ConnectError" in detail
    assert "503" in detail


@respx.mock
@pytest.mark.asyncio
async def test_non_json_body_reports_content_type_not_a_decode_error():
    """Hitting an HTML login page or a proxy error page should say so."""
    respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(
            200, text="<html>login</html>", headers={"Content-Type": "text/html"}
        )
    )

    with pytest.raises(SsfDiscoveryError) as exc:
        await fetch_ssf_configuration("https://idp.test")

    detail = str(exc.value)
    assert "not JSON" in detail
    assert "text/html" in detail


@respx.mock
@pytest.mark.asyncio
async def test_http_error_body_is_included_for_diagnosis():
    respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(401, text="invalid_token")
    )

    with pytest.raises(SsfDiscoveryError) as exc:
        await fetch_ssf_configuration("https://idp.test")

    assert "401" in str(exc.value)
    assert "invalid_token" in str(exc.value)


@respx.mock
@pytest.mark.asyncio
async def test_caller_supplied_client_is_not_closed():
    """The poller/stream-client inject a shared AsyncClient; closing it out
    from under them would break subsequent calls."""
    respx.get(f"https://idp.test{SSF_CONFIGURATION_SEGMENT}").mock(
        return_value=httpx.Response(200, json=METADATA)
    )

    async with httpx.AsyncClient() as shared:
        assert await fetch_ssf_configuration("https://idp.test", client=shared) == METADATA
        assert not shared.is_closed
