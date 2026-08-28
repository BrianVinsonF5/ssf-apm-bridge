from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import MIN_ADMIN_API_KEY_LENGTH, PLACEHOLDER_ADMIN_API_KEY, Settings

GOOD_KEY = "x" * MIN_ADMIN_API_KEY_LENGTH


def _settings(**overrides) -> Settings:
    # _env_file=None so a developer's real .env can't influence the result.
    return Settings(_env_file=None, **overrides)


def test_rejects_placeholder_admin_api_key():
    with pytest.raises(ValidationError, match="placeholder"):
        _settings(admin_api_key=PLACEHOLDER_ADMIN_API_KEY)


def test_rejects_short_admin_api_key():
    with pytest.raises(ValidationError, match="at least"):
        _settings(admin_api_key="too-short")


def test_rejects_non_ascii_admin_api_key():
    # hmac.compare_digest raises TypeError on non-ASCII str, so these are
    # refused at startup rather than 500ing on every authenticated request.
    with pytest.raises(ValidationError, match="ASCII"):
        _settings(admin_api_key="k\u00e9y" + "x" * MIN_ADMIN_API_KEY_LENGTH)


def test_accepts_a_real_key():
    assert _settings(admin_api_key=GOOD_KEY).admin_api_key == GOOD_KEY


def test_set_freshness_defaults_are_consistent_with_replay_ttl():
    s = _settings(admin_api_key=GOOD_KEY)
    # A SET must not outlive the replay guard's memory of its jti, or it
    # becomes replayable again once the jti is forgotten.
    assert s.replay_jti_ttl_seconds >= s.set_max_age_seconds
