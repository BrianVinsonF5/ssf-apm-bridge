"""Per-issuer JWKS cache used to verify SET signatures.

Transmitters rotate signing keys. We cache each issuer's key set for a
short TTL and, critically, refetch on a `kid` we don't recognize instead of
only refetching on a timer -- that's what keeps verification working
through a rotation without an outage window.
"""
from __future__ import annotations

import time

import httpx
from jwt import PyJWK, PyJWKClient
from jwt.exceptions import PyJWKClientError

JWKS_TTL_SECONDS = 3600


class IssuerNotRegistered(Exception):
    pass


class JWKSManager:
    def __init__(self) -> None:
        # issuer -> jwks_uri, populated at transmitter-registration time via
        # the transmitter's /.well-known/ssf-configuration document.
        self._jwks_uri_by_issuer: dict[str, str] = {}
        self._clients: dict[str, PyJWKClient] = {}
        self._client_created_at: dict[str, float] = {}

    def register_issuer(self, issuer: str, jwks_uri: str) -> None:
        self._jwks_uri_by_issuer[issuer] = jwks_uri
        self._clients.pop(issuer, None)

    def _client_for(self, issuer: str) -> PyJWKClient:
        jwks_uri = self._jwks_uri_by_issuer.get(issuer)
        if jwks_uri is None:
            raise IssuerNotRegistered(
                f"no jwks_uri registered for issuer {issuer!r}; "
                "register the transmitter first via POST /admin/transmitters"
            )

        stale = time.time() - self._client_created_at.get(issuer, 0) > JWKS_TTL_SECONDS
        if issuer not in self._clients or stale:
            self._clients[issuer] = PyJWKClient(jwks_uri, cache_keys=True, lifespan=JWKS_TTL_SECONDS)
            self._client_created_at[issuer] = time.time()
        return self._clients[issuer]

    def signing_key_for(self, issuer: str, token: str) -> PyJWK:
        """Resolve the signing key for `token`'s `kid`, refetching the JWKS
        once if the kid isn't in the cached set (handles rotation)."""
        client = self._client_for(issuer)
        try:
            return client.get_signing_key_from_jwt(token)
        except PyJWKClientError:
            # Unknown kid -- force a refetch and try exactly once more.
            self._clients.pop(issuer, None)
            client = self._client_for(issuer)
            return client.get_signing_key_from_jwt(token)


async def fetch_ssf_configuration(issuer_or_config_url: str, *, client: httpx.AsyncClient | None = None) -> dict:
    """Fetch a transmitter's /.well-known/ssf-configuration document.

    `issuer_or_config_url` may be a bare issuer (https://idp.example.com) --
    in which case we append the well-known path -- or the full metadata URL.
    """
    url = issuer_or_config_url
    if not url.rstrip("/").endswith("ssf-configuration"):
        url = url.rstrip("/") + "/.well-known/ssf-configuration"

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=10.0)
    try:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()
    finally:
        if owns_client:
            await client.aclose()


jwks_manager = JWKSManager()
