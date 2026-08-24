from __future__ import annotations

import httpx
import pytest
import respx

from app.bigip.client import BigIpApmClient, FastPathDisabled, InvalidSessionId
from app.config import settings


@pytest.fixture()
def client():
    return BigIpApmClient()


def test_terminate_session_noop_when_fast_path_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "bigip_enable_fast_path", False)
    with pytest.raises(FastPathDisabled):
        client.terminate_session("a1b2c3d4e5f6a1b2c3d4e5f6")


def test_terminate_session_rejects_malformed_session_id(client, monkeypatch):
    monkeypatch.setattr(settings, "bigip_enable_fast_path", True)
    with pytest.raises(InvalidSessionId):
        client.terminate_session("'; rm -rf /; echo pwned")


@respx.mock
def test_terminate_session_calls_tmsh_over_rest(client, monkeypatch):
    monkeypatch.setattr(settings, "bigip_enable_fast_path", True)
    monkeypatch.setattr(settings, "bigip_auth_mode", "token")

    login_route = respx.post(f"{settings.bigip_base_url}/mgmt/shared/authn/login").mock(
        return_value=httpx.Response(200, json={"token": {"token": "abc123", "timeout": 1200}})
    )
    bash_route = respx.post(f"{settings.bigip_base_url}/mgmt/tm/util/bash").mock(
        return_value=httpx.Response(200, json={"commandResult": ""})
    )

    client.terminate_session("a1b2c3d4e5f6a1b2c3d4e5f6", reason="session-revoked")

    assert login_route.called
    assert bash_route.called
    sent_body = bash_route.calls.last.request.content.decode()
    assert "delete apm session key a1b2c3d4e5f6a1b2c3d4e5f6" in sent_body
    assert bash_route.calls.last.request.headers["X-F5-Auth-Token"] == "abc123"


@respx.mock
def test_login_failure_raises_bigip_error(client, monkeypatch):
    from app.bigip.client import BigIpError

    monkeypatch.setattr(settings, "bigip_enable_fast_path", True)
    monkeypatch.setattr(settings, "bigip_auth_mode", "token")

    respx.post(f"{settings.bigip_base_url}/mgmt/shared/authn/login").mock(
        return_value=httpx.Response(401, json={"message": "bad creds"})
    )

    with pytest.raises(BigIpError):
        client.terminate_session("a1b2c3d4e5f6a1b2c3d4e5f6")
