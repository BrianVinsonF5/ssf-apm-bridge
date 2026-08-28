"""Poll-based delivery (RFC 8936) for transmitters that don't support push.

Each poll cycle: ask the transmitter for a batch of pending SETs,
process each one through the same verify -> enforce pipeline the push
endpoint uses, then ack the ones we successfully processed so the
transmitter can drop them.
"""
from __future__ import annotations

import logging
from typing import Awaitable, Callable

import httpx

from app.config import settings
from app.ssf.registry import TransmitterConfig

logger = logging.getLogger("ssf_bridge.poller")

SetHandler = Callable[[str, str], Awaitable[bool]]  # (issuer, raw_set_jwt) -> processed_ok


class PollDeliveryClient:
    def __init__(self, config: TransmitterConfig, access_token: str, *, http_client: httpx.AsyncClient | None = None):
        self._config = config
        self._token = access_token
        self._client = http_client or httpx.AsyncClient(
            timeout=15.0,
            verify=settings.get_httpx_verify(config.verify_tls),
        )
        self._owns_client = http_client is None
        self._poll_endpoint = config.configuration_endpoint  # set by caller to the transmitter's poll endpoint_url

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def poll_once(self, handler: SetHandler, *, max_events: int = 50) -> int:
        """Fetch and process one batch. Returns the number of SETs handled."""
        if not self._poll_endpoint:
            raise ValueError("no poll endpoint configured for this transmitter")

        resp = await self._client.post(
            self._poll_endpoint,
            json={"maxEvents": max_events, "returnImmediately": True},
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        payload = resp.json()
        sets: dict[str, str] = payload.get("sets", {})

        acked: list[str] = []
        for jti, raw_set in sets.items():
            ok = await handler(self._config.issuer, raw_set)
            if ok:
                acked.append(jti)

        if acked:
            await self._client.post(
                self._poll_endpoint,
                json={"ack": acked, "maxEvents": 0},
                headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
            )

        return len(acked)
