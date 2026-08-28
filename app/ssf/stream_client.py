"""SSF Stream Management API client.

This is the bridge acting as an SSF *receiver*: discover a transmitter,
create a push-delivery stream, subscribe subjects, and request a
verification event. Shapes follow the SSF 1.0 final spec's Configuration /
Status / Add-Subject / Remove-Subject / Verification endpoints.

https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
"""
from __future__ import annotations

from typing import Any

import httpx

from app.config import settings
from app.models import SubjectIdentifier
from app.security.jwks import fetch_ssf_configuration
from app.ssf.registry import TransmitterConfig

PUSH_DELIVERY_METHOD = "urn:ietf:rfc:8935"
POLL_DELIVERY_METHOD = "urn:ietf:rfc:8936"


class StreamManagementError(Exception):
    pass


class StreamManagementClient:
    """One instance per transmitter; holds the bearer token used to call
    that transmitter's stream-management API."""

    def __init__(self, config: TransmitterConfig, access_token: str, *, http_client: httpx.AsyncClient | None = None):
        self._config = config
        self._token = access_token
        self._client = http_client or httpx.AsyncClient(timeout=10.0, verify=settings.get_httpx_verify())
        self._owns_client = http_client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _post(self, url: str, body: dict[str, Any]) -> httpx.Response:
        resp = await self._client.post(url, json=body, headers=self._headers())
        if resp.status_code >= 400:
            raise StreamManagementError(f"POST {url} -> {resp.status_code}: {resp.text}")
        return resp

    async def create_push_stream(self, *, receiver_events_endpoint: str, events_requested: list[str], description: str = "ssf-apm-bridge") -> dict[str, Any]:
        if not self._config.configuration_endpoint:
            raise StreamManagementError("transmitter has no configuration_endpoint")
        body = {
            "delivery": {
                "method": PUSH_DELIVERY_METHOD,
                "endpoint_url": receiver_events_endpoint,
            },
            "events_requested": events_requested,
            "description": description,
        }
        resp = await self._post(self._config.configuration_endpoint, body)
        return resp.json()

    async def set_stream_status(self, *, stream_id: str, status: str, reason: str | None = None) -> dict[str, Any]:
        if status not in ("enabled", "paused", "disabled"):
            raise ValueError(f"invalid status {status!r}")
        if not self._config.status_endpoint:
            raise StreamManagementError("transmitter has no status_endpoint")
        body: dict[str, Any] = {"stream_id": stream_id, "status": status}
        if reason:
            body["reason"] = reason
        resp = await self._post(self._config.status_endpoint, body)
        return resp.json()

    async def add_subject(self, *, stream_id: str, subject: SubjectIdentifier, verified: bool = False) -> None:
        if not self._config.add_subject_endpoint:
            raise StreamManagementError("transmitter has no add_subject_endpoint")
        body = {"stream_id": stream_id, "subject": subject.model_dump(), "verified": verified}
        await self._post(self._config.add_subject_endpoint, body)

    async def remove_subject(self, *, stream_id: str, subject: SubjectIdentifier) -> None:
        if not self._config.remove_subject_endpoint:
            raise StreamManagementError("transmitter has no remove_subject_endpoint")
        body = {"stream_id": stream_id, "subject": subject.model_dump()}
        await self._post(self._config.remove_subject_endpoint, body)

    async def request_verification(self, *, stream_id: str, state: str | None = None) -> None:
        if not self._config.verification_endpoint:
            raise StreamManagementError("transmitter has no verification_endpoint")
        body: dict[str, Any] = {"stream_id": stream_id}
        if state:
            body["state"] = state
        await self._post(self._config.verification_endpoint, body)


async def discover_transmitter(issuer_or_config_url: str, *, access_token: str | None = None) -> dict[str, Any]:
    """Thin re-export so callers only need to import from this module when
    wiring up a new transmitter."""
    return await fetch_ssf_configuration(issuer_or_config_url, access_token=access_token)
