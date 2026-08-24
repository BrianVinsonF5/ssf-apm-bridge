"""Admin surface: register transmitters, either by hand (you already know
the endpoints/jwks_uri) or via SSF discovery (we fetch
/.well-known/ssf-configuration and create a push stream for you)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.security.auth import require_api_key
from app.security.jwks import fetch_ssf_configuration, jwks_manager
from app.ssf.registry import TransmitterConfig, transmitter_registry
from app.ssf.stream_client import StreamManagementClient, StreamManagementError

logger = logging.getLogger("ssf_bridge.admin")

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_api_key)])


@router.post("/transmitters", status_code=201)
async def register_transmitter_manual(config: TransmitterConfig) -> dict:
    """Register a transmitter you've already fully configured -- no
    discovery call, no stream creation. This is what the mock transmitter
    used for local demos calls."""
    transmitter_registry.register(config)
    jwks_manager.register_issuer(config.issuer, config.jwks_uri)
    return {"status": "registered", "issuer": config.issuer}


class DiscoverTransmitterBody(BaseModel):
    issuer_or_config_url: str
    access_token: str
    events_requested: list[str]
    expected_audience: str | None = None


@router.post("/transmitters/discover", status_code=201)
async def register_transmitter_via_discovery(body: DiscoverTransmitterBody) -> dict:
    """Fetch the transmitter's SSF metadata, register it, and create a
    push-delivery stream pointed at this bridge's /events endpoint."""
    try:
        metadata = await fetch_ssf_configuration(body.issuer_or_config_url)
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller either way
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
    )

    stream_client = StreamManagementClient(config, body.access_token)
    try:
        stream = await stream_client.create_push_stream(
            receiver_events_endpoint=f"{settings.receiver_base_url}/events",
            events_requested=body.events_requested,
        )
    except StreamManagementError as exc:
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
    jwks_manager.register_issuer(issuer, jwks_uri)

    logger.info("transmitter_registered_via_discovery: issuer=%s stream_id=%s", issuer, config.stream_id)
    return {"status": "registered", "issuer": issuer, "stream": stream}


@router.get("/transmitters")
async def list_transmitters() -> dict:
    return {"transmitters": [t.model_dump() for t in transmitter_registry.all()]}
