"""Correlation-key derivation.

These keys decide which APM session a signal enforces against, so a
collision between two distinct subjects is a security bug, not a cosmetic
one -- hence the explicit collision tests below.
"""
from __future__ import annotations

from app.models import SubjectIdentifier


def _key(data: dict) -> str:
    return SubjectIdentifier.model_validate(data).correlation_key()


def test_email_is_lowercased():
    assert _key({"format": "email", "email": "Alice@Example.COM"}) == "email:alice@example.com"


def test_phone_number_key():
    assert _key({"format": "phone_number", "phone_number": "+15551234567"}) == "phone:+15551234567"


def test_iss_sub_key():
    assert _key({"format": "iss_sub", "iss": "https://idp.test", "sub": "u1"}) == "iss_sub:https://idp.test|u1"


def test_opaque_key():
    assert _key({"format": "opaque", "id": "abc123"}) == "opaque:abc123"


def test_complex_subject_keys_off_user_member():
    assert (
        _key(
            {
                "format": "complex",
                "user": {"format": "email", "email": "bob@example.com"},
                "device": {"format": "opaque", "id": "dev-1"},
            }
        )
        == "email:bob@example.com"
    )


def test_complex_subjects_without_user_do_not_collide():
    """Regression: both of these used to produce the bare key "complex:",
    so a device-compliance signal for one device enforced against another."""
    a = _key({"format": "complex", "device": {"format": "opaque", "id": "dev-A"}})
    b = _key({"format": "complex", "device": {"format": "opaque", "id": "dev-B"}})

    assert a != b
    assert a != "complex:"
    assert b != "complex:"


def test_correlation_key_is_stable_across_member_ordering():
    a = _key({"format": "complex", "device": {"format": "opaque", "id": "d"}, "tenant": {"format": "opaque", "id": "t"}})
    b = _key({"format": "complex", "tenant": {"format": "opaque", "id": "t"}, "device": {"format": "opaque", "id": "d"}})
    assert a == b


def test_unknown_format_still_produces_distinct_keys():
    a = _key({"format": "future-format", "whatever": "one"})
    b = _key({"format": "future-format", "whatever": "two"})
    assert a != b
    assert a.startswith("future-format:")


def test_correlation_key_has_no_delimiters_that_break_redis_keys():
    # Keys are interpolated into f"ssf:decision:{key}" and a URL query string.
    key = _key({"format": "complex", "device": {"format": "opaque", "id": "dev with spaces/and:colons"}})
    assert " " not in key
    assert "/" not in key
