"""In-process registry of configured SSF transmitters.

An MVP-appropriate store: enough to run one bridge process against a
handful of transmitters. Swap for a real database once you need this
config to survive a restart or be shared across replicas.
"""
from __future__ import annotations

from pydantic import BaseModel


class TransmitterConfig(BaseModel):
    issuer: str
    jwks_uri: str
    configuration_endpoint: str | None = None
    status_endpoint: str | None = None
    add_subject_endpoint: str | None = None
    remove_subject_endpoint: str | None = None
    verification_endpoint: str | None = None
    stream_id: str | None = None
    # What we expect in the SET's `aud` claim from this transmitter --
    # normally the stream_id the transmitter assigned us at registration.
    expected_audience: str
    # Set False to skip TLS certificate verification for every outbound call
    # to this transmitter (discovery, stream management, JWKS, polling).
    # Lab/self-signed use only -- see the warning in app/admin.py.
    verify_tls: bool = True


class UnknownIssuer(Exception):
    pass


class TransmitterRegistry:
    def __init__(self) -> None:
        self._by_issuer: dict[str, TransmitterConfig] = {}

    def register(self, config: TransmitterConfig) -> None:
        self._by_issuer[config.issuer] = config

    def get(self, issuer: str) -> TransmitterConfig:
        cfg = self._by_issuer.get(issuer)
        if cfg is None:
            raise UnknownIssuer(f"no transmitter registered for issuer {issuer!r}")
        return cfg

    def all(self) -> list[TransmitterConfig]:
        return list(self._by_issuer.values())


transmitter_registry = TransmitterRegistry()
