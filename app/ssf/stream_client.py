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

# Legacy RISC-profile aliases for the same two families. Keycloak's SSF
# transmitter accepts all four URIs and collapses them into the `push` /
# `poll` families, so the `urn:` forms above are the correct modern choice;
# these are here for transmitters that only advertise the older strings.
RISC_PUSH_DELIVERY_METHOD = "https://schemas.openid.net/secevent/risc/delivery-method/push"
RISC_POLL_DELIVERY_METHOD = "https://schemas.openid.net/secevent/risc/delivery-method/poll"

# Scopes Keycloak's SSF stream-management API expects on the bearer token.
# `ssf.manage` covers create/update/delete, `ssf.read` covers the GETs
# (SsfAuthUtil.canManage/canRead -> checkScopePermission). Keycloak creates
# both as *optional* client scopes, so they are only granted when the token
# request explicitly asks for them -- a plain client-credentials token
# authenticates but is not authorized.
SSF_READ_SCOPE = "ssf.read"
SSF_MANAGE_SCOPE = "ssf.manage"
SSF_TOKEN_SCOPES = f"{SSF_READ_SCOPE} {SSF_MANAGE_SCOPE}"


class StreamManagementError(Exception):
    pass


class StreamManagementClient:
    """One instance per transmitter; holds the bearer token used to call
    that transmitter's stream-management API."""

    def __init__(self, config: TransmitterConfig, access_token: str, *, http_client: httpx.AsyncClient | None = None):
        self._config = config
        self._token = access_token
        # TLS policy comes from the transmitter's own config so a lab
        # transmitter with a self-signed cert stays reachable across restarts
        # without loosening verification globally.
        self._client = http_client or httpx.AsyncClient(
            timeout=10.0,
            verify=settings.get_httpx_verify(config.verify_tls),
        )
        self._owns_client = http_client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _post(self, url: str, body: dict[str, Any]) -> httpx.Response:
        resp = await self._client.post(url, json=body, headers=self._headers())
        if resp.status_code >= 400:
            raise StreamManagementError(self._describe_failure(url, resp))
        return resp

    def _describe_failure(self, url: str, resp: httpx.Response) -> str:
        """Build an error message that says *why* the call was rejected.

        For 401/403 the response body is often empty, and the actual reason
        lives in the RFC 6750 `WWW-Authenticate` challenge -- that header is
        what distinguishes an expired token from a wrong audience from a
        missing scope, so it must not be dropped.
        """
        parts = [f"POST {url} -> {resp.status_code}"]

        challenge = resp.headers.get("www-authenticate")
        if challenge:
            parts.append(f"WWW-Authenticate: {challenge}")

        body = resp.text.strip()
        parts.append(f"body: {body[:400]}" if body else "body: <empty>")

        if resp.status_code in (401, 403):
            parts.append(
                "the access_token was rejected by the transmitter's "
                "stream-management API. Keycloak collapses every distinct "
                "cause into the same bare 401 (empty body, no "
                "WWW-Authenticate), so an absent challenge here says nothing "
                "-- work through its gates in order: "
                "(1) the token authenticates at all -- unexpired, a JWT, and "
                "issued by THIS realm; "
                "(2) the client the token was issued to (its azp) has "
                "ssf.enabled=true on its SSF tab and the client itself is "
                "enabled; "
                "(3) unless ssf.requireServiceAccount=false, that client has "
                "service accounts turned on and the token is its OWN "
                "service-account token -- a client-credentials token from a "
                "different client, or any interactive user login, is refused "
                "even with the right scopes; "
                "(4) ssf.requiredRole, if set on the client, is present in "
                "the token; "
                f"(5) the token's scope claim contains {SSF_MANAGE_SCOPE!r} "
                f"(mint it with scope={SSF_TOKEN_SCOPES!r})"
            )
        elif resp.status_code == 409:
            # Keycloak allows exactly one stream per receiver client, so a
            # retry after a partial failure hits this rather than replacing
            # the existing stream.
            parts.append(
                "a stream already exists for this receiver client -- Keycloak "
                "permits only one, so delete the old stream (DELETE on the "
                "configuration_endpoint, or the SSF tab in the admin console) "
                "before creating a new one"
            )
        elif resp.status_code == 400:
            # The two request-shape rejections a receiver actually hits.
            parts.append(
                "the transmitter rejected the request body -- for Keycloak "
                "this is usually the push URL failing the receiver's "
                "ssf.validPushUrls allow-list (which must be non-empty and "
                "https), or a delivery method excluded by "
                "ssf.allowedDeliveryMethods"
            )
        return " | ".join(parts)

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


async def discover_transmitter(
    issuer_or_config_url: str,
    *,
    access_token: str | None = None,
    verify_tls: bool | None = None,
) -> dict[str, Any]:
    """Thin re-export so callers only need to import from this module when
    wiring up a new transmitter."""
    return await fetch_ssf_configuration(
        issuer_or_config_url,
        access_token=access_token,
        verify_tls=verify_tls,
    )
