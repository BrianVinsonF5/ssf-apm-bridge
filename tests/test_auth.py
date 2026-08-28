"""API-key auth on the control-plane endpoints."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.security.auth import require_api_key

# Any endpoint behind require_api_key. Uses the real POST route so the
# request reaches the auth dependency rather than stopping at a 405.
PROTECTED_PATH = "/correlation/sessions/lookup"
BODY = {"subject_key": "email:nobody@example.com"}


@pytest.fixture()
def client():
    return TestClient(app)


def _post(client, key: str | None):
    headers = {} if key is None else {"X-API-Key": key}
    return client.post(PROTECTED_PATH, json=BODY, headers=headers)


def test_valid_key_is_accepted(client):
    assert _post(client, settings.admin_api_key).status_code != 401


def test_missing_key_is_rejected(client):
    assert _post(client, None).status_code == 401


def test_wrong_key_is_rejected(client):
    assert _post(client, "wrong-key-but-right-length-0123456789").status_code == 401


def test_non_ascii_key_over_the_wire_is_rejected_not_a_500(client):
    """Regression: hmac.compare_digest raises TypeError on non-ASCII str, so
    this used to be an unhandled 500 rather than a clean 401.

    Sent as raw bytes because that's what a non-Python client can put on the
    wire; Starlette decodes header bytes as latin-1, yielding a str with
    non-ASCII characters.
    """
    resp = client.post(
        PROTECTED_PATH,
        json=BODY,
        headers={"X-API-Key": "p\u00e1ssw\u00f6rd-with-non-ascii-chars".encode("latin-1")},
    )
    assert resp.status_code == 401


def test_non_ascii_key_does_not_raise_in_the_dependency():
    """Same defect at the unit level, independent of client-side encoding."""
    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_api_key(x_api_key="p\u00e1ssw\u00f6rd-with-non-ascii-chars"))
    assert exc.value.status_code == 401


def test_key_that_is_a_prefix_of_the_real_one_is_rejected(client):
    assert _post(client, settings.admin_api_key[:-1]).status_code == 401
