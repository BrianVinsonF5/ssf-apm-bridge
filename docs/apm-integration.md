# Wiring BIG-IP APM to the bridge

Two integration points on the APM side. Both call the bridge's control-plane
API (`X-API-Key: $ADMIN_API_KEY`), not the public `/events` endpoint.

A honest caveat up front: **classic TMOS iRules have no simple built-in HTTP
client.** Two real options exist for making the outbound calls below, and
which one you pick should depend on what your team already maintains:

- **iRules LX (recommended)** -- write the actual HTTP call in Node.js,
  using a real HTTP client, and invoke it from the Tcl side with
  `ILX::call`. More code, but you get real error handling, timeouts, and
  JSON parsing instead of hand-rolling HTTP over a socket.
- **Classic Tcl `SIDEBAND::connect` / `SIDEBAND::send` / `SIDEBAND::recv`**
  -- lower-level, no iRules LX plugin required, but you're constructing
  raw HTTP requests and parsing raw responses by hand.
  (https://clouddocs.f5.com/api/irules/SIDEBAND.html)

The snippets below are Tcl-shaped pseudocode showing *what* to call and
*when*, not copy-paste-ready production iRules -- validate the exact
`SIDEBAND::*` or `ILX::call` syntax against your TMOS version in a lab
before shipping it.

## 1. Session registration (keeps the correlation store current)

Bind an iRule to your Access Profile's virtual server for these two events:

```tcl
when ACCESS_SESSION_STARTED {
    set session_id [ACCESS::session sid]
    set user_email [ACCESS::session data get session.saml.last.identity]
    # or session.oauth.client.last.userinfo, session.logon.last.username,
    # whichever your Access Policy actually populates

    # POST {"format":"email","email":$user_email,"apm_session_id":$session_id}
    # to https://<bridge>/correlation/sessions with X-API-Key -- via
    # SIDEBAND::connect/send/recv or an ILX::call into an iRules LX
    # extension that does the POST for you.
}

when ACCESS_SESSION_CLOSED {
    set session_id [ACCESS::session sid]
    # DELETE https://<bridge>/correlation/sessions/$session_id with X-API-Key
}
```

This is what makes the fast path's `session-revoked` / `account-disabled`
handling possible at all -- without it, the bridge has a subject identity
from the SET but no way to know which live APM session that corresponds
to.

## 2. Per-request decision lookup (continuous path)

Add an item to your **Per-Request Policy** (not the initial Access
Policy -- this needs to run on every request, not just at login) that:

1. Resolves the current subject's correlation key the same way the
   registration iRule did (e.g. `email:$user_email`).
2. Calls `GET https://<bridge>/internal/decision?subject_key=<key>` with
   `X-API-Key`.
3. On `404` -- no cached signal for this subject -- branch to **Allow**.
4. On `200` -- inspect the JSON body and branch:
   - `risk_level == "HIGH"` -- deny, or route to a step-up (MFA) branch.
   - `device_compliant == false` -- deny.
   - `assurance_level` below your policy floor -- route to step-up.
   - otherwise -- allow, and consider clearing/ignoring the stale record.

```tcl
# Per-Request Policy -> Subroutine -> iRule Event agent
when ACCESS_POLICY_AGENT_EVENT {
    if { [ACCESS::policy agent_id] eq "ssf_decision_lookup" } {
        set key "email:[ACCESS::session data get session.saml.last.identity]"
        # GET /internal/decision?subject_key=$key, parse JSON, set a
        # session variable (e.g. session.custom.ssf_risk) that a
        # downstream Branch Rule in the per-request policy reads.
    }
}
```

Keep this lookup on the shorter of your OAuth Token Validation Interval or
a fixed per-request cadence -- calling it on literally every single
request is the most correct behavior but also the most latency-sensitive;
measure before you commit to it in a high-QPS environment.

## 3. Fast-path session termination

Nothing to configure on the APM side for this one -- it's the bridge
calling *out* to BIG-IP (see `app/bigip/client.py`), not APM calling the
bridge. The one APM-side prerequisite: the account in `BIGIP_USERNAME`
needs "Advanced shell (bash)" access, since the fast path runs
`tmsh delete apm session key <id>` via the generic
`/mgmt/tm/util/bash` iControl REST endpoint (there's no dedicated REST
collection for APM sessions). If your environment disallows bash access
on service accounts -- common in hardened/PCI deployments -- the
supported alternative is an **iCall script** triggered by a custom
iControl REST worker, which can run tmsh commands with the box's own
local privilege rather than a REST-exposed shell. That's a bigger lift
than this MVP covers; flagged here so it doesn't surprise you later.

## Event -> per-request-policy action reference

See the main [README](../README.md#event-to-enforcement-mapping) and the
published [reference architecture](https://claude.ai/code/artifact/aa028acb-0ff7-48ad-b435-4514f2b266e4)
for the full CAEP/RISC event table this integration implements.
