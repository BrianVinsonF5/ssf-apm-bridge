"""Real iControl REST client for BIG-IP, used by the fast enforcement path.

Two things worth knowing before you point this at a real box:

1. There is no first-class iControl REST collection for APM active
   sessions (no `/mgmt/tm/apm/session`). The documented, supported way to
   list/kill one from automation is the `apm session` tmsh command
   (https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/apm/apm_session.html),
   so that's what this client runs -- via the generic
   `/mgmt/tm/util/bash` endpoint, which requires "Advanced shell (bash)"
   access on the account in BIGIP_USERNAME. Plenty of hardened/PCI
   environments turn that off; see docs/apm-integration.md for the
   iCall-script alternative if yours does.

2. `BIGIP_ENABLE_FAST_PATH` defaults to false. With it false, this client
   logs what it *would* have done and returns without calling the box --
   deliberately, so wiring this up against a real APM instance is an
   explicit opt-in, not a side effect of starting the bridge.
"""
from __future__ import annotations

import logging
import re
import time

import httpx

from app.config import settings

logger = logging.getLogger("ssf_bridge.bigip")

# BIG-IP APM session IDs are hex strings (observed length 26-32 chars
# depending on version). Validate before it ever reaches a shell command.
_SESSION_ID_RE = re.compile(r"^[a-fA-F0-9]{16,40}$")


class BigIpError(Exception):
    pass


class InvalidSessionId(BigIpError):
    pass


class FastPathDisabled(Exception):
    """Raised (and expected to be caught) when BIGIP_ENABLE_FAST_PATH is
    false -- callers should treat this as "logged, not executed", not as a
    failure."""


class BigIpApmClient:
    def __init__(self) -> None:
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._client = httpx.Client(
            base_url=settings.bigip_base_url,
            verify=settings.get_httpx_verify(settings.bigip_verify_tls),
            timeout=15.0,
        )

    # -- auth -----------------------------------------------------------

    def _login(self) -> None:
        resp = self._client.post(
            "/mgmt/shared/authn/login",
            json={
                "username": settings.bigip_username,
                "password": settings.bigip_password,
                "loginProviderName": "tmos",
            },
        )
        if resp.status_code >= 400:
            raise BigIpError(f"iControl REST login failed: {resp.status_code} {resp.text}")
        payload = resp.json()
        token_info = payload.get("token", {})
        self._token = token_info.get("token")
        timeout = token_info.get("timeout", 1200)
        self._token_expires_at = time.time() + timeout - 30  # renew a bit early
        if not self._token:
            raise BigIpError(f"iControl REST login response missing token: {payload}")

    def _auth_headers(self) -> dict[str, str]:
        if settings.bigip_auth_mode == "basic":
            return {}  # httpx.Client auth handles Basic
        if self._token is None or time.time() >= self._token_expires_at:
            self._login()
        return {"X-F5-Auth-Token": self._token}

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        auth = None
        if settings.bigip_auth_mode == "basic":
            auth = (settings.bigip_username, settings.bigip_password)
        resp = self._client.request(method, path, headers=headers, auth=auth, **kwargs)
        if resp.status_code == 401 and settings.bigip_auth_mode == "token":
            # token may have been revoked out-of-band; retry once with a fresh login
            self._token = None
            headers.update(self._auth_headers())
            resp = self._client.request(method, path, headers=headers, **kwargs)
        return resp

    # -- tmsh-over-REST ---------------------------------------------------

    def _run_tmsh(self, tmsh_command: str) -> str:
        resp = self._request(
            "POST",
            "/mgmt/tm/util/bash",
            json={"command": "run", "utilCmdArgs": f"-c \"tmsh -q -c '{tmsh_command}'\""},
        )
        if resp.status_code >= 400:
            raise BigIpError(f"tmsh-over-REST call failed: {resp.status_code} {resp.text}")
        return resp.json().get("commandResult", "")

    # -- public API --------------------------------------------------------

    def terminate_session(self, apm_session_id: str, *, reason: str = "") -> None:
        if not _SESSION_ID_RE.match(apm_session_id):
            raise InvalidSessionId(f"refusing to act on session id {apm_session_id!r}: doesn't look like a BIG-IP APM session id")

        if not settings.bigip_enable_fast_path:
            logger.warning(
                "fast_path_disabled: would terminate apm_session_id=%s reason=%r "
                "(set BIGIP_ENABLE_FAST_PATH=true to actually call BIG-IP)",
                apm_session_id,
                reason,
            )
            raise FastPathDisabled(apm_session_id)

        result = self._run_tmsh(f"delete apm session key {apm_session_id}")
        logger.info("terminated apm_session_id=%s reason=%r result=%r", apm_session_id, reason, result.strip())

    def list_sessions_raw(self) -> str:
        """Best-effort passthrough of `tmsh list apm session all-properties`
        for debugging/admin use -- not parsed, not on the enforcement path."""
        return self._run_tmsh("list apm session all-properties")

    def close(self) -> None:
        self._client.close()


bigip_client = BigIpApmClient()
