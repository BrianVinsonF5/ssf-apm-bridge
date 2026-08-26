# ssf-apm-bridge

An OpenID [Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
(SSF) receiver that bridges CAEP and RISC event streams into
[F5 BIG-IP APM](https://techdocs.f5.com/en-us/bigip-17-1-0/big-ip-access-policy-manager-oauth-configuration/apm-oauth-client-and-resource-server.html)
enforcement.

BIG-IP APM has no native SSF transmitter or receiver role -- there's
nothing in the product that speaks the stream-management API or parses a
Security Event Token. This service is the piece that doesn't exist off
the shelf: it registers with your identity provider, device-management
platform, and risk engine as an SSF receiver, verifies incoming SETs, and
drives APM's existing extensibility (per-request policy, iRules, the
OAuth client/resource-server agents) to actually enforce what those
signals say.

Full architectural writeup, with a diagram:
**[Shared Signals Bridge -- reference architecture](https://claude.ai/code/artifact/aa028acb-0ff7-48ad-b435-4514f2b266e4)**

## How it enforces

Not every event carries the same urgency, so the bridge splits at
dispatch time instead of forcing everything through one mechanism:

- **Fast path** -- `session-revoked`, `account-disabled`,
  `account-purged`, `sessions-revoked`. The bridge resolves the subject
  to a live APM session via its correlation store and terminates it
  directly against BIG-IP (near-real-time, not bounded by APM's
  per-request cadence).
- **Continuous path** -- `risk-level-change`, `device-compliance-change`,
  `assurance-level-change`, `token-claims-change`. The bridge writes a
  keyed record to a decision cache; APM's per-request policy reads it on
  every request and allows, steps up, or denies accordingly.
- **Informational** -- everything else (`session-established`,
  `opt-in`/`opt-out-*`, etc.) is logged for audit and correlation but
  doesn't trigger an enforcement action on its own.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

cp .env.example .env
# at minimum, set a real ADMIN_API_KEY

uvicorn app.main:app --reload --port 8080
```

In a second terminal, run the zero-dependency end-to-end demo -- it spins
up a throwaway JWKS server, registers itself as a transmitter, registers
a fake APM session, and pushes sample CAEP events:

```bash
export ADMIN_API_KEY=<same value as in .env>
python tools/mock_transmitter.py
```

Watch the bridge's own stdout for `event_processed` log lines showing
what it did with each event. `BIGIP_ENABLE_FAST_PATH` defaults to
`false`, so the `session-revoked` scenario logs what it *would* have
terminated rather than calling a real BIG-IP -- flip that once you point
`BIGIP_HOST` at an actual box.

Run the test suite:

```bash
pip install -r requirements-dev.txt
pytest -v
```

Or with Docker (bridge + Redis, `STORE_BACKEND=redis`):

```bash
docker compose up --build
```

Or deploy to **Kubernetes** (automated build, secrets, Redis backend, service, and ingress):

Linux/macOS:
```bash
./deploy.sh
```

Windows PowerShell:
```powershell
.\deploy.ps1
```

Or manually with `kubectl`:
```bash
kubectl apply -f k8s/
```


## Wiring it to a real transmitter and a real BIG-IP

1. **Register a transmitter.** Either hand it fully-formed config:
   `POST /admin/transmitters` with `issuer`, `jwks_uri`,
   `expected_audience`, and the four stream-management endpoint URLs; or
   let the bridge do discovery and create the push stream for you:
   `POST /admin/transmitters/discover` with `issuer_or_config_url` and an
   `access_token` for that transmitter's stream-management API.
2. **Wire BIG-IP APM.** Set `BIGIP_HOST` / `BIGIP_USERNAME` /
   `BIGIP_PASSWORD`, set `BIGIP_ENABLE_FAST_PATH=true` once you've
   validated it in a lab, and add the iRules / per-request-policy items
   described in [docs/apm-integration.md](docs/apm-integration.md) so APM
   registers sessions with the bridge and consults the decision cache.
3. **Point real signals at it.** Your IdP, UEM/EDR, and risk engine each
   need to support pushing to (or being polled from) the bridge's
   `/events` endpoint as an SSF transmitter.

## Event-to-enforcement mapping

| Event | Profile | Path | APM action |
|---|---|---|---|
| `session-revoked` | CAEP | fast | Terminate the identified session(s) immediately. |
| `token-claims-change` | CAEP | continuous | Refresh cached claims; re-evaluate policy branches keyed on them. |
| `credential-change` | CAEP | continuous | Update policy state / flag for review. |
| `assurance-level-change` | CAEP | continuous | Tighten/relax access tier; step-up if below policy floor. |
| `device-compliance-change` | CAEP | continuous | Deny/restrict on non-compliant; restore on remediation. |
| `session-established` | CAEP | informational | Inventory / correlate. |
| `session-presented` | CAEP | informational | Session-inventory freshness check. |
| `risk-level-change` | CAEP | continuous | Adjust policy tier; step-up or deny at HIGH. |
| `account-credential-change-required` | RISC | fast | Terminate sessions; force re-auth with new credential. |
| `account-purged` | RISC | fast | Terminate sessions; purge correlation record. |
| `account-disabled` | RISC | fast | Terminate all sessions for the account. |
| `account-enabled` | RISC | informational | No auto-restore; user still re-authenticates through the IdP. |
| `identifier-changed` / `identifier-recycled` | RISC | informational | Correlation remap -- not yet automated in this MVP, see below. |
| `recovery-activated` | RISC | continuous | Flag for step-up while account recovery is in progress. |
| `sessions-revoked` | RISC | fast | Terminate all sessions (deprecated in RISC in favor of CAEP `session-revoked`, still handled). |

`app/enforcement/router.py` is the source of truth (`EVENT_PATHS`) --
these are judgment calls, not spec requirements, and are meant to be
edited for your risk tolerance.

## API reference

All endpoints except `/events`, `/health`, and `/readyz` require
`X-API-Key: $ADMIN_API_KEY`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/events` | RFC 8935 push delivery target for transmitters. |
| `POST` | `/admin/transmitters` | Register a transmitter with config you already have. |
| `POST` | `/admin/transmitters/discover` | Discover + register a transmitter and create a push stream. |
| `GET` | `/admin/transmitters` | List registered transmitters. |
| `POST` | `/correlation/sessions` | Register a subject -> APM session mapping (called by BIG-IP). |
| `DELETE` | `/correlation/sessions/{id}` | Deregister a session (called by BIG-IP on logout/timeout). |
| `POST` | `/correlation/sessions/lookup` | Debug: look up sessions for a subject. |
| `GET` | `/internal/decision?subject_key=...` | Continuous-path lookup (called by APM's per-request policy). |
| `GET` | `/health` / `/readyz` | Liveness/readiness. |

Interactive docs at `/docs` once the server is running.

## What's genuinely MVP here (not production-hardened)

- **Subject correlation is in-memory by default.** Set
  `STORE_BACKEND=redis` before running more than one bridge replica, or
  before a restart losing all session correlation is unacceptable.
- **Session ownership across an APM HA pair/cluster isn't resolved.** An
  APM session lives on exactly one device; `terminate_session` calls
  whatever `BIGIP_HOST` points at. In a multi-device deployment you need
  to either track which device owns which session (extend
  `CorrelationRecord.bigip_device`, already there but unused by the
  client) or fan the kill call out to every candidate.
- **`identifier-changed` / `identifier-recycled` don't remap the
  correlation store.** They're logged informationally; wiring an actual
  remap needs the event payload's old/new identifier pair, which isn't
  modeled yet.
- **The fast-path BIG-IP call runs tmsh over the generic
  `/mgmt/tm/util/bash` REST endpoint**, because there's no first-class
  REST collection for APM sessions. This requires Advanced shell access
  on the service account -- see
  [docs/apm-integration.md](docs/apm-integration.md) for the hardened
  alternative.
- **No poll-delivery scheduler is wired into `main.py` yet** --
  `app/ssf/poller.py` implements RFC 8936 polling, but nothing calls it
  on a timer. Push delivery (RFC 8935, via `/events`) is what's actually
  exercised end to end.

## Project layout

```
app/
  models.py              SET/subject/event models, CAEP+RISC event URIs
  security/
    jwks.py               per-issuer JWKS cache + discovery fetch
    set_verifier.py        SET signature/claims verification
    auth.py                X-API-Key dependency for internal endpoints
  ssf/
    registry.py             configured transmitters
    stream_client.py        SSF stream-management API client
    push_receiver.py        POST /events (RFC 8935)
    poller.py                RFC 8936 poll delivery (not yet scheduled)
  correlation/
    store.py                subject -> APM session id (memory/Redis)
    router_api.py            registration API BIG-IP calls
  decision/
    cache.py                 continuous-path signal cache (memory/Redis)
    api.py                    lookup API APM's per-request policy calls
  enforcement/
    router.py                 the event -> path mapping table + dispatch
  bigip/
    client.py                  real iControl REST client, fast-path kill
  replay_guard.py           jti replay protection
  admin.py                  transmitter registration endpoints
  main.py                   FastAPI app wiring
tests/                    pytest suite (SET verification, enforcement
                           routing, BIG-IP client against mocked HTTP,
                           push receiver end to end)
tools/mock_transmitter.py Zero-dependency end-to-end demo
docs/apm-integration.md   BIG-IP-side iRule / per-request-policy wiring
```

## References

- [OpenID Shared Signals Framework Specification 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [OpenID Continuous Access Evaluation Profile (CAEP) 1.0](https://openid.net/specs/openid-caep-1_0-final.html)
- [OpenID RISC Event Types 1.0](https://openid.net/specs/openid-risc-event-types-1_0.html)
- [F5 iRules APM command reference](https://clouddocs.f5.com/api/irules/APM.html)
- [F5 tmsh `apm session` reference](https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/apm/apm_session.html)
- [BIG-IP APM OAuth Client and Resource Server](https://techdocs.f5.com/en-us/bigip-17-1-0/big-ip-access-policy-manager-oauth-configuration/apm-oauth-client-and-resource-server.html)
