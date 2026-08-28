"""Per-issuer JWKS cache used to verify SET signatures.

Transmitters rotate signing keys. We cache each issuer's key set for a
short TTL and, critically, refetch on a `kid` we don't recognize instead of
only refetching on a timer -- that's what keeps verification working
through a rotation without an outage window.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit, urlunsplit

import httpx
from jwt import PyJWK, PyJWKClient
from jwt.exceptions import PyJWKClientError

from app.config import settings

JWKS_TTL_SECONDS = 3600

SSF_CONFIGURATION_SEGMENT = "/.well-known/ssf-configuration"


class IssuerNotRegistered(Exception):
    pass


class SsfDiscoveryError(Exception):
    """Discovery of a transmitter's SSF metadata failed.

    Carries the URL(s) actually attempted, because the underlying httpx
    exceptions do not -- an operator seeing only "Server disconnected
    without sending a response." has no way to tell which URL was tried.
    """


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
            self._clients[issuer] = PyJWKClient(
                jwks_uri,
                cache_keys=True,
                lifespan=JWKS_TTL_SECONDS,
                ssl_context=settings.get_ssl_context(),
            )
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


def ssf_configuration_urls(issuer_or_config_url: str) -> list[str]:
    """Candidate metadata URLs for `issuer_or_config_url`, in priority order.

    If the caller already handed us a full metadata URL, that's the only
    candidate. Otherwise we derive two, because both conventions are in use:

    1. RFC 8414 / SSF: the well-known segment is *inserted* between the
       authority and the issuer's path, so issuer
       `https://kc.example.com/realms/x` becomes
       `https://kc.example.com/.well-known/ssf-configuration/realms/x`.
    2. The older "just append it" form,
       `https://kc.example.com/realms/x/.well-known/ssf-configuration`,
       which several transmitters actually serve.

    For a path-less issuer both forms collapse to the same URL, so the list
    is deduplicated and usually has a single entry.
    """
    if issuer_or_config_url.rstrip("/").endswith("ssf-configuration"):
        return [issuer_or_config_url]

    parts = urlsplit(issuer_or_config_url.rstrip("/"))
    issuer_path = parts.path.rstrip("/")

    rfc8414 = urlunsplit((parts.scheme, parts.netloc, SSF_CONFIGURATION_SEGMENT + issuer_path, "", ""))
    appended = urlunsplit((parts.scheme, parts.netloc, issuer_path + SSF_CONFIGURATION_SEGMENT, "", ""))

    # dict.fromkeys keeps insertion order while dropping the duplicate that
    # a path-less issuer produces.
    return list(dict.fromkeys([rfc8414, appended]))


async def fetch_ssf_configuration(
    issuer_or_config_url: str,
    *,
    client: httpx.AsyncClient | None = None,
    access_token: str | None = None,
) -> dict:
    """Fetch a transmitter's /.well-known/ssf-configuration document.

    `issuer_or_config_url` may be a bare issuer (https://idp.example.com) --
    in which case we derive the well-known URL(s) -- or the full metadata URL.

    Redirects are followed: an IdP that 302s http->https or /realms/x ->
    /realms/x/ would otherwise return a 302 that raise_for_status() ignores,
    and we'd fail later in .json() with an opaque decode error.

    Raises SsfDiscoveryError, whose message names every URL attempted and the
    underlying failure for each.
    """
    candidates = ssf_configuration_urls(issuer_or_config_url)

    headers = {"Accept": "application/json"}
    if access_token:
        # SSF 1.0 s7.1.1 permits a protected Transmitter Configuration
        # endpoint; harmless on an open one.
        headers["Authorization"] = f"Bearer {access_token}"

    owns_client = client is None
    client = client or httpx.AsyncClient(
        timeout=10.0,
        verify=settings.get_httpx_verify(),
        follow_redirects=True,
    )
    failures: list[str] = []
    try:
        for url in candidates:
            try:
                resp = await client.get(url, headers=headers, follow_redirects=True)
            except httpx.HTTPError as exc:
                # Transport-level: DNS, TLS, connect timeout, or the peer
                # hanging up mid-request. Class name matters as much as the
                # message when diagnosing, so keep both.
                failures.append(f"GET {url} -> {type(exc).__name__}: {exc}")
                continue

            if resp.status_code >= 400:
                failures.append(f"GET {url} -> HTTP {resp.status_code}: {resp.text[:200]}")
                continue

            try:
                return resp.json()
            except ValueError as exc:
                ctype = resp.headers.get("content-type", "unknown")
                failures.append(
                    f"GET {url} -> HTTP {resp.status_code} but body was not JSON "
                    f"(content-type={ctype}): {exc}"
                )
                continue

        raise SsfDiscoveryError(
            f"could not fetch SSF configuration for {issuer_or_config_url!r}; "
            f"attempted {len(candidates)} URL(s): " + " | ".join(failures)
        )
    finally:
        if owns_client:
            await client.aclose()


jwks_manager = JWKSManager()
