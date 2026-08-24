"""Data shapes for SETs, subjects, and the CAEP/RISC event catalog.

Event type URIs are copied verbatim from the OpenID final specs:
  - CAEP 1.0:        https://openid.net/specs/openid-caep-1_0-final.html
  - RISC event types: https://openid.net/specs/openid-risc-event-types-1_0.html

Note: the final RISC event-types spec does not define a standalone
"credential-compromise" URI (an earlier draft profile mentioned one). A
compromised credential is expressed as `account-credential-change-required`
(force a reset) or `account-disabled` (lock the account now) depending on
severity -- both are mapped on the fast path below.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CaepEventType(str, Enum):
    SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    TOKEN_CLAIMS_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
    CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    ASSURANCE_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
    DEVICE_COMPLIANCE_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
    SESSION_ESTABLISHED = "https://schemas.openid.net/secevent/caep/event-type/session-established"
    SESSION_PRESENTED = "https://schemas.openid.net/secevent/caep/event-type/session-presented"
    RISK_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"


class RiscEventType(str, Enum):
    ACCOUNT_CREDENTIAL_CHANGE_REQUIRED = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
    ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
    ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
    ACCOUNT_ENABLED = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
    IDENTIFIER_CHANGED = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
    IDENTIFIER_RECYCLED = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
    OPT_IN = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
    OPT_OUT_INITIATED = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
    OPT_OUT_CANCELLED = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
    OPT_OUT_EFFECTIVE = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"
    RECOVERY_ACTIVATED = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
    RECOVERY_INFORMATION_CHANGED = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"
    SESSIONS_REVOKED = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"


KNOWN_EVENT_TYPES: set[str] = {e.value for e in CaepEventType} | {e.value for e in RiscEventType}


class EnforcementPath(str, Enum):
    FAST = "fast"          # terminate the session now
    CONTINUOUS = "continuous"  # update the decision cache, let per-request policy react
    INFORMATIONAL = "informational"  # log / correlate only, no enforcement action


class SubjectIdentifier(BaseModel):
    """A SSF subject per the Subject Identifiers for SETs spec.

    `format` is one of "email", "phone_number", "iss_sub", "opaque",
    "complex", etc. Extra fields vary by format, so this stays permissive
    and normalization happens in `.correlation_key()`.
    """

    model_config = ConfigDict(extra="allow")

    format: str

    def correlation_key(self) -> str:
        """Produce a stable string key for the correlation store.

        Complex subjects (e.g. {"format": "complex", "user": {...}, "device":
        {...}}) key off the "user" sub-identifier when present, since that's
        what an APM session is ultimately tied to; device/tenant qualifiers
        are appended so a lookup can still disambiguate if needed.
        """
        data = self.model_dump()
        fmt = data.get("format")

        if fmt == "email":
            return f"email:{data.get('email', '').lower()}"
        if fmt == "phone_number":
            return f"phone:{data.get('phone_number', '')}"
        if fmt == "iss_sub":
            return f"iss_sub:{data.get('iss', '')}|{data.get('sub', '')}"
        if fmt == "opaque":
            return f"opaque:{data.get('id', '')}"
        if fmt == "complex":
            user = data.get("user")
            if isinstance(user, dict):
                nested = SubjectIdentifier.model_validate(user)
                return nested.correlation_key()
        # Fall back to a deterministic (if verbose) key so nothing is silently dropped.
        items = sorted((k, v) for k, v in data.items() if k != "format" and isinstance(v, (str, int, float)))
        return f"{fmt}:" + "|".join(f"{k}={v}" for k, v in items)


class SecurityEventToken(BaseModel):
    """The decoded, verified claims of a SET (RFC 8417 + SSF profile)."""

    model_config = ConfigDict(extra="allow")

    iss: str
    iat: int
    jti: str
    aud: str | list[str]
    sub_id: SubjectIdentifier
    events: dict[str, dict[str, Any]]

    @field_validator("events")
    @classmethod
    def _must_have_one_event(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not v:
            raise ValueError("SET 'events' claim must contain at least one event")
        return v

    def primary_event_type(self) -> str:
        """SETs may technically carry more than one event; SSF receivers in
        practice act on the (typically single) event type present."""
        return next(iter(self.events.keys()))

    def primary_event_payload(self) -> dict[str, Any]:
        return self.events[self.primary_event_type()]


class DecisionRecord(BaseModel):
    """What the continuous path writes to the decision cache and what
    BIG-IP's per-request policy reads back."""

    subject_key: str
    risk_level: Literal["LOW", "MEDIUM", "HIGH"] | None = None
    device_compliant: bool | None = None
    assurance_level: str | None = None
    changed_claims: dict[str, Any] | None = None
    reason: str | None = None
    source_event: str | None = None
    updated_at: float = Field(default_factory=lambda: time.time())


class CorrelationRecord(BaseModel):
    """Maps a subject to the live APM session(s) that authenticated it."""

    subject_key: str
    apm_session_id: str
    bigip_device: str | None = None  # which node in an HA pair/cluster owns it
    apm_username: str | None = None
    registered_at: float = Field(default_factory=lambda: time.time())
