"""Entrypoint that starts the listener from `settings`.

Exists because inbound TLS cannot be expressed in a static `CMD`: the
keypair paths come from configuration, and a NodePort has nothing in front
of it to terminate TLS on the service's behalf, so uvicorn has to be handed
the certificate itself.

Run with `python -m app` (see the Dockerfile). For local development
`uvicorn app.main:app --reload` still works and simply serves plaintext.
"""
from __future__ import annotations

import logging
import os
import sys

import uvicorn

from app.audit import configure_logging
from app.config import settings

logger = logging.getLogger("ssf_bridge.startup")


def _tls_kwargs() -> dict[str, str]:
    """Resolve the keypair, refusing to start if it isn't usable.

    Failing fast matters more than availability here. cert-manager
    populates its secret asynchronously, so a bridge that quietly fell back
    to http on a missing file would bind cleartext on the port operators
    published as https -- exposing ADMIN_API_KEY and every SET to anyone on
    the path. A crash-looping pod is loud and safe; a silent downgrade is
    neither.
    """
    if not settings.tls_enabled:
        logger.warning(
            "inbound_tls_disabled: serving plaintext HTTP on %s:%s -- "
            "ADMIN_API_KEY travels in a header, so only do this behind a "
            "proxy that terminates TLS. Set TLS_CERT_FILE and TLS_KEY_FILE "
            "to serve https directly (required for a NodePort, which does "
            "not terminate TLS).",
            settings.host,
            settings.port,
        )
        return {}

    for label, path in (
        ("TLS_CERT_FILE", settings.tls_cert_file),
        ("TLS_KEY_FILE", settings.tls_key_file),
    ):
        if not os.path.exists(path):
            logger.error(
                "inbound_tls_unusable: %s=%s does not exist. If this is a "
                "cert-manager secret, confirm the Certificate was issued "
                "('kubectl get certificate -n ssf-bridge') and that the "
                "secret is mounted into the pod. Refusing to start rather "
                "than downgrade to plaintext http.",
                label,
                path,
            )
            sys.exit(1)
        if os.path.getsize(path) == 0:
            logger.error(
                "inbound_tls_unusable: %s=%s is empty. Refusing to start "
                "rather than downgrade to plaintext http.",
                label,
                path,
            )
            sys.exit(1)

    logger.info(
        "inbound_tls_enabled: serving HTTPS on %s:%s cert=%s",
        settings.host,
        settings.port,
        settings.tls_cert_file,
    )
    return {
        "ssl_certfile": settings.tls_cert_file,
        "ssl_keyfile": settings.tls_key_file,
    }


def main() -> None:
    configure_logging()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        **_tls_kwargs(),
    )


if __name__ == "__main__":
    main()
