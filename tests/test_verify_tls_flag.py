"""The `verify_tls` opt-out must reach *every* outbound call to a
transmitter, not just the discovery request that carried it.

The JWKS fetch is the one that matters most: it happens later, during SET
verification, long after the admin request is gone. If the flag were not
persisted, discovery would succeed against a self-signed transmitter and
then every SET from it would fail to verify.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.config import settings
from app.security.jwks import JWKSManager
from app.ssf.poller import PollDeliveryClient
from app.ssf.registry import TransmitterConfig
from app.ssf.stream_client import StreamManagementClient

ISSUER = "https://selfsigned.test"


def _config(verify_tls: bool | None = None) -> TransmitterConfig:
    kwargs = {} if verify_tls is None else {"verify_tls": verify_tls}
    return TransmitterConfig(
        issuer=ISSUER,
        jwks_uri=f"{ISSUER}/.well-known/jwks.json",
        configuration_endpoint=f"{ISSUER}/ssf/stream",
        expected_audience="https://bridge.test/events",
        **kwargs,
    )


def test_verify_tls_defaults_to_true_on_the_model():
    """Existing callers and stored configs must keep verifying."""
    assert _config().verify_tls is True


def test_verify_tls_is_accepted_from_json():
    cfg = TransmitterConfig.model_validate(
        {
            "issuer": ISSUER,
            "jwks_uri": f"{ISSUER}/jwks",
            "expected_audience": "aud",
            "verify_tls": False,
        }
    )
    assert cfg.verify_tls is False


def _captured_verify(monkeypatch, cls) -> list:
    captured = []
    real_init = cls.__init__

    def spy(self, *args, verify=True, **kwargs):
        captured.append(verify)
        return real_init(self, *args, verify=verify, **kwargs)

    monkeypatch.setattr(cls, "__init__", spy)
    return captured


def test_stream_client_honours_verify_tls_false(monkeypatch):
    captured = _captured_verify(monkeypatch, httpx.AsyncClient)
    StreamManagementClient(_config(verify_tls=False), "token")
    assert captured == [False]


def test_stream_client_verifies_by_default(monkeypatch):
    monkeypatch.setattr(settings, "ca_bundle_path", "")
    captured = _captured_verify(monkeypatch, httpx.AsyncClient)
    StreamManagementClient(_config(), "token")
    assert captured == [True]


def test_poller_honours_verify_tls_false(monkeypatch):
    captured = _captured_verify(monkeypatch, httpx.AsyncClient)
    PollDeliveryClient(_config(verify_tls=False), "token")
    assert captured == [False]


# --- the JWKS path: flag must survive registration --------------------


def _captured_ssl_context(monkeypatch) -> list:
    """PyJWKClient takes an ssl_context, not a bool, so assert on the
    resulting context's verify_mode."""
    import app.security.jwks as jwks_mod

    captured = []

    class FakePyJWKClient:
        def __init__(self, uri, **kwargs):
            captured.append(kwargs.get("ssl_context"))

    monkeypatch.setattr(jwks_mod, "PyJWKClient", FakePyJWKClient)
    return captured


def test_jwks_client_skips_verification_for_a_verify_tls_false_issuer(monkeypatch):
    import ssl

    captured = _captured_ssl_context(monkeypatch)
    mgr = JWKSManager()
    mgr.register_issuer(ISSUER, f"{ISSUER}/jwks", verify_tls=False)

    mgr._client_for(ISSUER)

    assert len(captured) == 1
    ctx = captured[0]
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_jwks_client_verifies_for_a_normal_issuer(monkeypatch):
    import ssl

    monkeypatch.setattr(settings, "ca_bundle_path", "")
    captured = _captured_ssl_context(monkeypatch)
    mgr = JWKSManager()
    mgr.register_issuer(ISSUER, f"{ISSUER}/jwks")

    mgr._client_for(ISSUER)

    ctx = captured[0]
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_reregistering_an_issuer_can_re_enable_verification(monkeypatch):
    """Registering again with the default must not inherit the old opt-out."""
    import ssl

    monkeypatch.setattr(settings, "ca_bundle_path", "")
    captured = _captured_ssl_context(monkeypatch)
    mgr = JWKSManager()

    mgr.register_issuer(ISSUER, f"{ISSUER}/jwks", verify_tls=False)
    mgr._client_for(ISSUER)
    mgr.register_issuer(ISSUER, f"{ISSUER}/jwks")
    mgr._client_for(ISSUER)

    assert captured[0].verify_mode == ssl.CERT_NONE
    assert captured[1].verify_mode == ssl.CERT_REQUIRED


# --- end to end through the admin API ---------------------------------


@respx.mock
def test_discover_persists_verify_tls_onto_the_registered_transmitter():
    """The whole point: `verify_tls: false` in the request body must end up
    on the stored config so later JWKS/stream calls use it too."""
    from fastapi.testclient import TestClient

    from app.main import app
    from app.security.jwks import jwks_manager
    from app.ssf.registry import transmitter_registry

    base = "https://keycloak.test:30182"
    issuer = f"{base}/realms/demo"
    respx.get(f"{base}/.well-known/ssf-configuration/realms/demo").mock(
        return_value=httpx.Response(
            200,
            json={
                "issuer": issuer,
                "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
                "configuration_endpoint": f"{issuer}/ssf/streams",
            },
        )
    )
    respx.post(f"{issuer}/ssf/streams").mock(
        return_value=httpx.Response(201, json={"stream_id": "s-1", "aud": "aud-1"})
    )

    resp = TestClient(app).post(
        "/admin/transmitters/discover",
        headers={"X-API-Key": settings.admin_api_key},
        json={
            "issuer_or_config_url": issuer,
            "access_token": "tok",
            "events_requested": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
            "verify_tls": False,
        },
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["verify_tls"] is False
    assert transmitter_registry.get(issuer).verify_tls is False
    # ...and the JWKS manager learned it too, for the later SET verification.
    assert jwks_manager._verify_tls_by_issuer[issuer] is False


def test_manual_registration_persists_verify_tls():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.ssf.registry import transmitter_registry

    issuer = "https://manual-selfsigned.test"
    resp = TestClient(app).post(
        "/admin/transmitters",
        headers={"X-API-Key": settings.admin_api_key},
        json={
            "issuer": issuer,
            "jwks_uri": f"{issuer}/jwks",
            "expected_audience": "aud",
            "verify_tls": False,
        },
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["verify_tls"] is False
    assert transmitter_registry.get(issuer).verify_tls is False


def test_disabling_verification_is_logged_as_a_warning(caplog):
    """Never silent: this is a security-relevant downgrade."""
    from app.admin import _warn_if_tls_verification_disabled

    with caplog.at_level("WARNING", logger="ssf_bridge.admin"):
        _warn_if_tls_verification_disabled("https://selfsigned.test", False)
    assert "tls_verification_disabled" in caplog.text
    assert "https://selfsigned.test" in caplog.text


def test_no_warning_when_verification_stays_on(caplog):
    from app.admin import _warn_if_tls_verification_disabled

    with caplog.at_level("WARNING", logger="ssf_bridge.admin"):
        _warn_if_tls_verification_disabled("https://good.test", True)
    assert "tls_verification_disabled" not in caplog.text


# --- the push URL the transmitter has to allow-list -------------------
#
# Keycloak rejects push stream creation with an opaque 400 when the URL is
# not https or is absent from the receiver client's ssf.validPushUrls. Both
# are knowable from RECEIVER_BASE_URL before the request is even sent, so
# they are called out at that point rather than after a round trip.


def test_plaintext_push_url_is_flagged_before_the_transmitter_rejects_it(caplog):
    from app.admin import _warn_if_push_url_looks_unreachable

    with caplog.at_level("WARNING", logger="ssf_bridge.admin"):
        _warn_if_push_url_looks_unreachable("http://10.1.1.6:30808/events")
    assert "push_url_not_https" in caplog.text
    assert "http://10.1.1.6:30808/events" in caplog.text


def test_placeholder_receiver_base_url_is_flagged(caplog):
    """The shipped ConfigMap value cannot be in anyone's allow-list, so
    leaving it in place guarantees the 400."""
    from app.admin import _warn_if_push_url_looks_unreachable

    with caplog.at_level("WARNING", logger="ssf_bridge.admin"):
        _warn_if_push_url_looks_unreachable("https://ssf-bridge.example.com/events")
    assert "push_url_is_placeholder" in caplog.text


def test_a_real_https_push_url_is_not_flagged(caplog):
    from app.admin import _warn_if_push_url_looks_unreachable

    with caplog.at_level("WARNING", logger="ssf_bridge.admin"):
        _warn_if_push_url_looks_unreachable("https://ssf-bridge.f5demos.com/events")
    assert "push_url_not_https" not in caplog.text
    assert "push_url_is_placeholder" not in caplog.text
