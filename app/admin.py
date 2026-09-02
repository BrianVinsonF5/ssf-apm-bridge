"""Admin surface: register transmitters, either by hand (you already know
the endpoints/jwks_uri) or via SSF discovery (we fetch
/.well-known/ssf-configuration and create a push stream for you)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.security.auth import require_api_key
from app.security.jwks import fetch_ssf_configuration, jwks_manager, ssf_configuration_urls
from app.ssf.registry import TransmitterConfig, transmitter_registry
from app.ssf.stream_client import StreamManagementClient, StreamManagementError

logger = logging.getLogger("ssf_bridge.admin")

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_api_key)])


def _warn_if_tls_verification_disabled(issuer_or_url: str, verify_tls: bool) -> None:
    """Leave a loud, permanent audit trail. Disabling verification means any
    party able to intercept the connection can impersonate the transmitter
    and inject session-revocation events, so this must never be silent."""
    if not verify_tls:
        logger.warning(
            "tls_verification_disabled: target=%s -- certificate and hostname "
            "checks are OFF for all outbound calls to this transmitter "
            "(discovery, stream management, JWKS, polling). "
            "Do not use outside a lab; prefer setting CA_BUNDLE_PATH.",
            issuer_or_url,
        )


def _warn_if_push_url_looks_unreachable(push_url: str) -> None:
    """Flag a push URL the transmitter will refuse before we even send it.

    Keycloak's SSRF gate requires the URL to be `https` (and to match a
    non-empty `ssf.validPushUrls` entry on the receiver client), and a URL
    still carrying the shipped `example.com` placeholder cannot be in any
    real allow-list. Both surface as an opaque 400 from the transmitter, so
    say it here where the actual value is known.
    """
    if not push_url.startswith("https://"):
        logger.warning(
            "push_url_not_https: push_url=%s -- Keycloak rejects non-https "
            "push targets unless the server was started with "
            "allow-insecure-push-targets. Set RECEIVER_BASE_URL to the "
            "https address the transmitter can reach.",
            push_url,
        )
    if "example.com" in push_url or "example.internal" in push_url:
        logger.warning(
            "push_url_is_placeholder: push_url=%s -- RECEIVER_BASE_URL is "
            "still a shipped placeholder, so it cannot match the receiver "
            "client's ssf.validPushUrls allow-list and stream creation will "
            "fail with a 400.",
            push_url,
        )


@router.post("/transmitters", status_code=201)
async def register_transmitter_manual(config: TransmitterConfig) -> dict:
    """Register a transmitter you've already fully configured -- no
    discovery call, no stream creation. This is what the mock transmitter
    used for local demos calls.

    Accepts `verify_tls: false` to skip certificate verification on
    outbound calls to this transmitter (including the later JWKS fetch).
    """
    _warn_if_tls_verification_disabled(config.issuer, config.verify_tls)
    transmitter_registry.register(config)
    jwks_manager.register_issuer(config.issuer, config.jwks_uri, verify_tls=config.verify_tls)
    return {"status": "registered", "issuer": config.issuer, "verify_tls": config.verify_tls}


class DiscoverTransmitterBody(BaseModel):
    issuer_or_config_url: str
    access_token: str
    events_requested: list[str]
    expected_audience: str | None = None
    # Skip TLS certificate/hostname verification for every outbound call to
    # this transmitter. Defaults to the SSF_VERIFY_TLS setting (normally
    # True). Self-signed lab transmitters only.
    verify_tls: bool | None = None


@router.post("/transmitters/discover", status_code=201)
async def register_transmitter_via_discovery(body: DiscoverTransmitterBody) -> dict:
    """Fetch the transmitter's SSF metadata, register it, and create a
    push-delivery stream pointed at this bridge's /events endpoint.

    Accepts `verify_tls: false` to skip certificate verification for every
    outbound call to this transmitter. The choice is persisted on the
    registered transmitter so the later JWKS fetch (which happens during SET
    verification, not here) uses the same policy.
    """
    verify_tls = settings.ssf_verify_tls if body.verify_tls is None else body.verify_tls
    _warn_if_tls_verification_disabled(body.issuer_or_config_url, verify_tls)

    try:
        metadata = await fetch_ssf_configuration(
            body.issuer_or_config_url,
            access_token=body.access_token,
            verify_tls=verify_tls,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller either way
        # Log with the traceback: the 502 body is all the caller sees, and
        # transport errors like "Server disconnected without sending a
        # response." are undiagnosable without knowing the URL and the
        # exception class behind them.
        logger.warning(
            "discovery_failed: input=%s candidate_urls=%s error=%s",
            body.issuer_or_config_url,
            ssf_configuration_urls(body.issuer_or_config_url),
            exc,
            exc_info=True,
        )
        raise HTTPException(status_code=502, detail=f"discovery failed: {exc}") from exc

    issuer = metadata.get("issuer")
    jwks_uri = metadata.get("jwks_uri")
    if not issuer or not jwks_uri:
        raise HTTPException(status_code=502, detail=f"ssf-configuration missing issuer/jwks_uri: {metadata}")

    config = TransmitterConfig(
        issuer=issuer,
        jwks_uri=jwks_uri,
        configuration_endpoint=metadata.get("configuration_endpoint"),
        status_endpoint=metadata.get("status_endpoint"),
        add_subject_endpoint=metadata.get("add_subject_endpoint"),
        remove_subject_endpoint=metadata.get("remove_subject_endpoint"),
        verification_endpoint=metadata.get("verification_endpoint"),
        expected_audience=body.expected_audience or settings.receiver_base_url,
        verify_tls=verify_tls,
    )

    push_url = f"{settings.receiver_base_url}/events"
    _warn_if_push_url_looks_unreachable(push_url)

    stream_client = StreamManagementClient(config, body.access_token)
    try:
        stream = await stream_client.create_push_stream(
            receiver_events_endpoint=push_url,
            events_requested=body.events_requested,
        )
    except StreamManagementError as exc:
        # Discovery already succeeded by this point, so the transmitter is
        # reachable and the failure is about the request itself (usually the
        # access_token or the push URL). Log it rather than leaving only the
        # 502 body, and include the push URL: it is the value the operator
        # has to match in ssf.validPushUrls.
        logger.warning(
            "stream_creation_failed: issuer=%s configuration_endpoint=%s "
            "push_url=%s error=%s",
            issuer,
            config.configuration_endpoint,
            push_url,
            exc,
        )
        raise HTTPException(status_code=502, detail=f"stream creation failed: {exc}") from exc
    finally:
        await stream_client.aclose()

    config.stream_id = stream.get("stream_id")
    returned_aud = stream.get("aud")
    if returned_aud and body.expected_audience is None:
        # Trust what the transmitter actually put in the stream config over
        # our default guess, since that's what will show up in the SET's
        # `aud` claim.
        config.expected_audience = returned_aud[0] if isinstance(returned_aud, list) else returned_aud

    transmitter_registry.register(config)
    jwks_manager.register_issuer(issuer, jwks_uri, verify_tls=verify_tls)

    logger.info(
        "transmitter_registered_via_discovery: issuer=%s stream_id=%s verify_tls=%s",
        issuer,
        config.stream_id,
        verify_tls,
    )
    return {"status": "registered", "issuer": issuer, "stream": stream, "verify_tls": verify_tls}


@router.get("/transmitters")
async def list_transmitters() -> dict:
    return {"transmitters": [t.model_dump() for t in transmitter_registry.all()]}
