"""Inbound TLS: the listener terminates TLS itself.

A Kubernetes NodePort is plain L4 forwarding, so nothing between the caller
and the container can hold a certificate -- serving https on the node port
means uvicorn is handed the cert-manager keypair directly.

The failure mode being defended against throughout: a process that binds
plaintext http on the port operators published as https. ADMIN_API_KEY
travels in a header and SETs can terminate user sessions, so a silent
downgrade is worse than not starting at all.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import MIN_ADMIN_API_KEY_LENGTH, Settings

GOOD_KEY = "x" * MIN_ADMIN_API_KEY_LENGTH


def _settings(**overrides) -> Settings:
    # _env_file=None blocks a developer's real .env, but NOT os.environ --
    # pydantic still reads that -- so the TLS fields are pinned empty here
    # and overridden per-test. Without this, an exported TLS_CERT_FILE in
    # the shell silently changes what these tests assert.
    base = {"tls_cert_file": "", "tls_key_file": ""}
    base.update(overrides)
    return Settings(_env_file=None, admin_api_key=GOOD_KEY, **base)


# --- configuration ----------------------------------------------------


def test_tls_is_off_by_default():
    """Existing plaintext deployments behind an Ingress keep working."""
    s = _settings()
    assert s.tls_enabled is False
    assert s.public_scheme == "http"


def test_both_halves_enables_tls(tmp_path):
    crt, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    s = _settings(tls_cert_file=str(crt), tls_key_file=str(key))
    assert s.tls_enabled is True
    assert s.public_scheme == "https"


def test_cert_without_key_is_refused():
    """Half-configured TLS cannot serve https, and the fallback would be
    cleartext on a port advertised as https."""
    with pytest.raises(ValidationError, match="TLS_KEY_FILE"):
        _settings(tls_cert_file="/etc/ssf-bridge/tls/tls.crt")


def test_key_without_cert_is_refused():
    with pytest.raises(ValidationError, match="TLS_CERT_FILE"):
        _settings(tls_key_file="/etc/ssf-bridge/tls/tls.key")


def test_half_configured_error_names_both_env_vars():
    """The message has to be actionable from a crash-looping pod's logs."""
    with pytest.raises(ValidationError) as exc:
        _settings(tls_cert_file="/only/the/cert")
    detail = str(exc.value)
    assert "TLS_CERT_FILE" in detail
    assert "TLS_KEY_FILE" in detail


# --- the launcher's keypair resolution --------------------------------


def _tls_kwargs_with(monkeypatch, **overrides):
    from app import __main__ as launcher
    from app.config import settings as live_settings

    for field, value in overrides.items():
        monkeypatch.setattr(live_settings, field, value)
    return launcher._tls_kwargs()


def test_keypair_is_passed_to_uvicorn(monkeypatch, tmp_path):
    crt, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    crt.write_text("-----BEGIN CERTIFICATE-----\n")
    key.write_text("-----BEGIN PRIVATE KEY-----\n")

    kwargs = _tls_kwargs_with(
        monkeypatch, tls_cert_file=str(crt), tls_key_file=str(key)
    )
    assert kwargs == {"ssl_certfile": str(crt), "ssl_keyfile": str(key)}


def test_no_tls_configured_yields_no_ssl_kwargs(monkeypatch):
    assert _tls_kwargs_with(monkeypatch, tls_cert_file="", tls_key_file="") == {}


def test_plaintext_start_is_logged_as_a_warning(monkeypatch, caplog):
    """Never silent: this is the mode that leaks the API key."""
    with caplog.at_level("WARNING", logger="ssf_bridge.startup"):
        _tls_kwargs_with(monkeypatch, tls_cert_file="", tls_key_file="")
    assert "inbound_tls_disabled" in caplog.text


def test_missing_cert_file_exits_rather_than_serving_plaintext(monkeypatch, tmp_path):
    """cert-manager populates its secret asynchronously, so "configured but
    not there yet" is a real state -- and must not become a cleartext
    listener on the port published as https."""
    key = tmp_path / "tls.key"
    key.write_text("-----BEGIN PRIVATE KEY-----\n")

    with pytest.raises(SystemExit) as exc:
        _tls_kwargs_with(
            monkeypatch,
            tls_cert_file=str(tmp_path / "absent.crt"),
            tls_key_file=str(key),
        )
    assert exc.value.code == 1


def test_missing_key_file_exits(monkeypatch, tmp_path):
    crt = tmp_path / "tls.crt"
    crt.write_text("-----BEGIN CERTIFICATE-----\n")

    with pytest.raises(SystemExit):
        _tls_kwargs_with(
            monkeypatch,
            tls_cert_file=str(crt),
            tls_key_file=str(tmp_path / "absent.key"),
        )


def test_empty_cert_file_exits(monkeypatch, tmp_path):
    """An empty file is what a not-yet-populated mount looks like."""
    crt, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    crt.write_text("")
    key.write_text("-----BEGIN PRIVATE KEY-----\n")

    with pytest.raises(SystemExit):
        _tls_kwargs_with(monkeypatch, tls_cert_file=str(crt), tls_key_file=str(key))


def test_unusable_keypair_says_which_path_and_why(monkeypatch, tmp_path, caplog):
    key = tmp_path / "tls.key"
    key.write_text("-----BEGIN PRIVATE KEY-----\n")
    absent = tmp_path / "absent.crt"

    with caplog.at_level("ERROR", logger="ssf_bridge.startup"):
        with pytest.raises(SystemExit):
            _tls_kwargs_with(
                monkeypatch, tls_cert_file=str(absent), tls_key_file=str(key)
            )

    assert "inbound_tls_unusable" in caplog.text
    assert str(absent) in caplog.text
    # Point at the cert-manager Certificate, the usual culprit in k8s.
    assert "cert-manager" in caplog.text
