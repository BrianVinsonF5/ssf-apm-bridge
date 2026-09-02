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
# Required: set a real ADMIN_API_KEY. The service refuses to start while it
# is the placeholder, under 32 chars, or non-ASCII.
python -c "import secrets; print(secrets.token_urlsafe(32))"

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

### External access (NodePort, HTTPS)

Until an Ingress controller is in place, [`k8s/05-service.yaml`](k8s/05-service.yaml) is a
`NodePort` service so that a REST client and the BIG-IP can both reach the bridge from
outside the cluster:

| Setting | Value |
| --- | --- |
| Service type | `NodePort` |
| Cluster-internal | `ssf-apm-bridge-service.ssf-bridge.svc.cluster.local:443` |
| External | `https://<node-ip>:30808` |
| Container port | `8443` (TLS) |

**TLS is terminated by the pod, not by the Service.** A NodePort is plain L4
packet forwarding — there is no proxy in that path that could hold a
certificate, so a Service cannot add TLS to a plaintext backend. uvicorn is
therefore handed the cert-manager keypair directly via `TLS_CERT_FILE` /
`TLS_KEY_FILE` ([`k8s/01-configmap.yaml`](k8s/01-configmap.yaml)), mounted
read-only from the `ssf-bridge-tls` secret.

Two consequences worth internalising before you call it:

1. **Callers must trust the issuing CA.** Export the `lab-ca-issuer` CA once
   and point your client at it (`--cacert`); the bridge presents a lab-CA-signed
   leaf, not a publicly-trusted one.
   ```bash
   kubectl get secret ssf-bridge-tls -n ssf-bridge \
     -o jsonpath='{.data.ca\.crt}' | base64 -d > lab-ca.crt
   curl --cacert lab-ca.crt https://<node-ip>:30808/health
   ```
2. **The node address you dial must be a SAN on the certificate.** Hostname
   verification is done against whatever you dialled, so
   `https://10.1.1.6:30808` fails unless `10.1.1.6` is in the Certificate's
   `ipAddresses`. The shipped `Certificate` covers `ssf-bridge.f5demos.com`
   and the in-cluster service name; uncomment `ipAddresses` in
   [`k8s/07-cert-manager.yaml`](k8s/07-cert-manager.yaml) and add the node
   addresses the BIG-IP actually dials:
   ```bash
   kubectl get nodes -o wide   # then add these to dnsNames / ipAddresses
   ```
   Prefer pointing a DNS name at the node and using that instead — IP SANs
   have to be re-issued whenever a node is replaced.

Certificate lifecycle: the `Certificate` renews at 75 days of a 90-day
lifetime, and the kubelet propagates the rewritten secret to the mounted
volume within about a minute. **uvicorn reads the keypair only at start-up**,
so restart the pods after a renewal or the listener keeps serving the old
leaf:

```bash
kubectl rollout restart deploy/ssf-apm-bridge -n ssf-bridge
```

If the keypair is missing or empty the container **exits non-zero rather than
falling back to HTTP** — a silent downgrade would publish `ADMIN_API_KEY` in
cleartext on the node port. `ContainerCreating` that never resolves means the
`ssf-bridge-tls` secret does not exist yet:

```bash
kubectl get certificate -n ssf-bridge
kubectl describe certificate ssf-bridge-certificate -n ssf-bridge
kubectl logs -n ssf-bridge deploy/ssf-apm-bridge | Select-String inbound_tls
```

To deliberately run plaintext behind a TLS-terminating Ingress, clear **both**
`TLS_CERT_FILE` and `TLS_KEY_FILE` and set `PORT` back to `8080` (setting only
one is refused at start-up).

Find a node IP and confirm the port is allocated:

```bash
kubectl get svc ssf-apm-bridge-service -n ssf-bridge
kubectl get nodes -o wide
```

Then point your REST client at it (all admin/correlation/decision routes require the
`X-API-Key` header; `/health` and `/readyz` do not):

```bash
curl --cacert lab-ca.crt https://<node-ip>:30808/health
curl --cacert lab-ca.crt \
  -H "X-API-Key: $ADMIN_API_KEY" https://<node-ip>:30808/admin/transmitters
```

Configure the BIG-IP per-request policy connector to call
`https://<node-ip>:30808/internal/decision?subject_key=<key>` (see
[`docs/apm-integration.md`](docs/apm-integration.md)). The BIG-IP must trust
the lab CA for that call — import `lab-ca.crt` into a `ltm profile server-ssl`
/ the sideband trust store, or the connector fails the handshake.

> **The API key is still only as safe as the network.** TLS now protects it in
> transit, but restrict access to the node port to the BIG-IP self-IP and your
> admin workstation anyway. The certificate is signed by a *lab* CA, so
> clients that skip verification gain nothing from it being HTTPS.

**Cloud clusters (EKS/AKS/GKE):** a NodePort only works if the node's security group
or firewall permits inbound TCP `30808` from the caller, and if the nodes are reachable
from the BIG-IP at all — nodes in private subnets are not reachable from outside the
VPC. On EKS, add an inbound rule for `30808` to the node group security group from the
BIG-IP's address, or use `kubectl port-forward` for local REST-client testing:

```bash
kubectl port-forward -n ssf-bridge svc/ssf-apm-bridge-service 8080:80
```

### Custom CA Trust & cert-manager

- **Internal CA Trust (BIG-IP APM & Keycloak SSF)**: Paste your enterprise root/intermediate CA certificate PEM into [`k8s/08-internal-ca-configmap.yaml`](file:///c:/Users/vinson/OneDrive%20-%20F5,%20Inc/Code/ssf-apm-bridge/k8s/08-internal-ca-configmap.yaml). It is mounted at `/etc/ssl/certs/ca-bundle.crt` inside the container with `SSL_CERT_FILE` and `CA_BUNDLE_PATH` set so python's `httpx` and `PyJWKClient` trust internal HTTPS endpoints.
- **cert-manager TLS Issuance**: [`k8s/07-cert-manager.yaml`](file:///c:/Users/vinson/OneDrive%20-%20F5,%20Inc/Code/ssf-apm-bridge/k8s/07-cert-manager.yaml) defines a `Certificate` (`ssf-bridge-certificate`) that requests a keypair from the cluster's existing `lab-ca-issuer` `ClusterIssuer` into the `ssf-bridge-tls` secret. That secret serves both the pod's own HTTPS listener and the Ingress.

### GitHub Container Registry (GHCR) & CI/CD

- **GitHub Actions**: Automated workflow [`.github/workflows/docker-publish.yml`](file:///c:/Users/vinson/OneDrive%20-%20F5,%20Inc/Code/ssf-apm-bridge/.github/workflows/docker-publish.yml) builds and pushes the image to `ghcr.io/brianvinsonf5/ssf-apm-bridge:latest` on every push to `main`.
- **Manual Push via Script**:
  ```bash
  PUSH_IMAGE=true ./deploy.sh
  ```
  or in PowerShell:
  ```powershell
  .\deploy.ps1 -PushImage
  ```
- **Private Package Pull Secret**: [`k8s/09-ghcr-secret.yaml`](file:///c:/Users/vinson/OneDrive%20-%20F5,%20Inc/Code/ssf-apm-bridge/k8s/09-ghcr-secret.yaml) provides a template secret if package visibility is set to private.




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

### Troubleshooting discovery (`POST /admin/transmitters/discover`)

A failure here returns `502` with `{"detail": "discovery failed: ..."}`.
The detail names **every URL attempted** and the underlying error for each,
and the same information is logged at `WARNING` with a full traceback:

```
kubectl logs -n ssf-bridge deploy/ssf-apm-bridge | Select-String discovery_failed
```

`issuer_or_config_url` accepts either a bare issuer or a full metadata URL.
For a bare issuer *with a path* (e.g. Keycloak's
`https://kc.example.com/realms/corp`) two candidates are tried in order:
the RFC 8414 form `https://kc.example.com/.well-known/ssf-configuration/realms/corp`,
then the appended form `https://kc.example.com/realms/corp/.well-known/ssf-configuration`.
Redirects are followed, and `access_token` is sent as a bearer token on the
metadata request as well as on stream creation.

Reading the error:

| Error in the detail | Means | Usual fix |
|---|---|---|
| `RemoteProtocolError: Server disconnected without sending a response.` | TCP connected, peer closed before sending any HTTP bytes | Almost always a scheme/port mismatch — `http://` against a TLS port, or `https://` against a plaintext one. Also seen when the endpoint requires mTLS, or a firewall/mesh sidecar RSTs the connection. |
| `ConnectError` / `All connection attempts failed` | Nothing listening, or egress blocked | Check the host/port and any egress NetworkPolicy or security group. |
| `ConnectTimeout` | Packets silently dropped | Firewall dropping rather than rejecting; check routing from the node's subnet. |
| `SSLCertVerificationError` | Internal CA not trusted, or self-signed cert | Populate [`k8s/08-internal-ca-configmap.yaml`](k8s/08-internal-ca-configmap.yaml) and restart the pods. For a lab transmitter, send `"verify_tls": false` (see below). |
| `HTTP 401` / `403` | Metadata endpoint is protected | Supply a valid `access_token`. |
| `HTTP 404` on both candidates | Neither well-known convention matches | Pass the exact metadata URL as `issuer_or_config_url`. |
| `body was not JSON (content-type=text/html)` | Reached a login page or proxy error page | You're hitting a proxy or the wrong vhost. |

There is no `curl` in the `python:3.12-slim` image; probe with the bundled
httpx from inside the pod so you exercise the real network path:

```
kubectl exec -n ssf-bridge deploy/ssf-apm-bridge -- \
  python -c "import httpx; r=httpx.get('<url>', timeout=10, follow_redirects=True); print(r.status_code, r.text[:300])"
```

### `stream creation failed: ... 400 ... requires the receiver client to declare ssf.validPushUrls`

```
{"error":"stream_error","error_description":"delivery method 'push' requires
 the receiver client to declare ssf.validPushUrls"}
```

This is **not** a bridge bug and not a token problem — discovery and
authorization both already succeeded. Keycloak's SSRF gate refuses to push to
any URL the receiver client has not pre-declared, and the receiver client
here has an **empty** `ssf.validPushUrls`. Keycloak names the attribute but
never the URL, so the bridge appends the push URL it actually sent:

```
| the push URL sent was 'https://ssf-bridge.f5demos.com/events' -- add exactly
this URL, or a trailing-* prefix of it, to the receiver client's SSF tab ->
Valid push URLs (ssf.validPushUrls)
```

Fix it in two places, in this order:

1. **Make `RECEIVER_BASE_URL` the address Keycloak can actually reach.** The
   push URL is `${RECEIVER_BASE_URL}/events`;
   [`k8s/01-configmap.yaml`](k8s/01-configmap.yaml) sets
   `https://ssf-bridge.f5demos.com`, which must match the `Certificate` in
   [`k8s/07-cert-manager.yaml`](k8s/07-cert-manager.yaml) and resolve from
   Keycloak. Allow-listing a name Keycloak cannot reach just moves the
   failure to delivery time. The bridge logs `push_url_is_placeholder` /
   `push_url_not_https` at `WARNING` before sending, so check:

   ```
   kubectl logs -n ssf-bridge deploy/ssf-apm-bridge | Select-String push_url
   ```

   Keycloak requires **https** with a **non-private, resolvable host**. The
   NodePort form now satisfies the scheme requirement (the pod terminates TLS),
   but `https://<node-ip>:30808` still fails on the *host* rule whenever that
   is a private address — refused unless the server was started with
   `allow-insecure-push-targets` — and Keycloak must also trust the lab CA
   that signed the bridge's certificate. Prefer the Ingress hostname from
   [`k8s/06-ingress.yaml`](k8s/06-ingress.yaml).
2. **Add that exact URL** to the receiver client's **SSF tab → Valid push
   URLs**. Entries are exact-match or trailing-`*`
   (`https://ssf-bridge.f5demos.com/*`); a bare `*` is ignored. Confirm
   **Push** is also ticked under supported delivery methods
   (`ssf.allowedDeliveryMethods`).

**No reachable https URL for the bridge?** Then push delivery is not
available to you and this 400 cannot be configured away. Keycloak also
supports poll delivery (RFC 8936), which reverses the direction so the
transmitter never needs to reach the bridge —
[`app/ssf/poller.py`](app/ssf/poller.py) implements the client half, but
`/admin/transmitters/discover` only creates **push** streams today, so a
poll stream has to be created out-of-band and registered with
`POST /admin/transmitters`.

### `stream creation failed: ... 401`

Discovery succeeded (the transmitter is reachable and its metadata parsed)
but the `POST` to `configuration_endpoint` was rejected. The error now
includes the `WWW-Authenticate` challenge, which is where the real reason
lives when the body is empty:

```
stream_creation_failed: issuer=... configuration_endpoint=... error=POST ... -> 401 |
WWW-Authenticate: Bearer error="invalid_token", error_description="Token is not active" | body: <empty>
```

**A bare 401 with no `WWW-Authenticate` and an empty body is the _normal_
shape of every SSF authorization failure — it is not a separate signal.**
Keycloak's receiver gate is a plain boolean check that ends in
`Response.status(UNAUTHORIZED).build()`
([`SsfAuthUtil.checkScopePermission`](https://github.com/keycloak/keycloak/blob/main/ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/support/SsfAuthUtil.java)),
so it never emits an RFC 6750 challenge. Do **not** read the missing header
as "the request never reached bearer evaluation" — that points you at the
feature flag and the proxy when the real cause is almost always the token.

Five distinct conditions produce that identical 401, and **a missing scope is
only one of them.** Keycloak checks them in this order:

| # | Gate | What satisfies it |
|---|---|---|
| 1 | Token authenticates | Unexpired, a JWT, issued by **this** realm |
| 2 | `ssf.enabled=true` on the client, and the client is enabled | The SSF tab of the client named in the token's **`azp`** |
| 3 | Service-account identity — unless `ssf.requireServiceAccount=false` | *Service accounts roles* on, and the token is that client's **own** service-account token |
| 4 | `ssf.requiredRole` (only if set on the client) | Role present in the token |
| 5 | Scope claim contains `ssf.manage` (`ssf.read` for the GETs) | `scope=ssf.read ssf.manage` on the token request |

Gate 3 is the trap: it compares the token user's `serviceAccountClientLink`
against the receiver client's internal id, so a **client-credentials token
from a _different_ client is refused even with both scopes**, and so is any
interactive user login. Check the token's `azp` and `preferred_username`
(expect `service-account-<clientId>`) and confirm `ssf.enabled=true` is set on
*that* client. See [the setup steps below](#where-to-get-the-access_token-from-keycloak).

**Isolate the failing gate with one extra request.** `GET`ting the same
`/streams` URL is authorized on `ssf.read` while `POST` needs `ssf.manage`,
but gates 1–4 are shared. So if `GET` succeeds and `POST` 401s, only
`ssf.manage` is missing; if both 401, the cause is one of gates 1–4. The probe
does this comparison for you, and also decodes the token's `azp` /
`preferred_username`:

```
python tools/probe_ssf_endpoint.py \
  --issuer https://keycloak.f5demos.com:30182/realms/geointdemo \
  --access-token "<token>" --client-id ssf-bridge --client-secret <secret> --insecure
```

If `userinfo` returns 200 with the same token, gate 1 is satisfied — the token
is live — and the cause is one of gates 2–5, i.e. receiver configuration or
scopes rather than credentials. The probe also repeats the call **without** a
token; here that 401 *should* look identical to the authenticated one, because
Keycloak returns the same bare 401 either way, so treat that as expected
rather than as evidence of a stripped `Authorization` header.

The `access_token` you pass is **not** the bridge's `ADMIN_API_KEY` — it is a
token the *transmitter* issued for its own SSF Stream Management API. Common
causes, in order:

1. **Missing the `ssf.read` / `ssf.manage` scopes.** Keycloak creates both as
   **optional** client scopes
   ([`SsfScopes`](https://github.com/keycloak/keycloak/blob/main/ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/SsfScopes.java)
   calls `addDefaultClientScope(scope, false)`), so they are only granted when
   the token request explicitly asks for them — a plain client-credentials
   token authenticates but is refused.
2. **Not the receiver client's own service-account token.** Gate 3 above.
   Requesting the scopes from a *different* client, or using a password /
   direct-access-grant token, fails identically. Set
   `ssf.requireServiceAccount=false` on the client only if you deliberately
   want to relax this.
3. **`ssf.enabled` not set on the client.** Keycloak only treats a client as
   an SSF Receiver when the `ssf.enabled=true` client attribute is present;
   a normal OIDC client calling `/streams` is not a receiver at all. It must
   be set on the client in the token's `azp`.
4. **Expired.** These are usually short-lived; a token minted minutes earlier
   may already be dead. Decode it and check `exp`:
   `python -c "import jwt,sys; print(jwt.decode(sys.argv[1], options={'verify_signature': False}))" <token>`
5. **`ssf.requiredRole` set but absent from the token.** Only applies when the
   client carries that attribute; the value is `roleName` for a realm role or
   `clientId.roleName` for a client role.
6. **Opaque vs JWT.** If the transmitter issued a reference token, its SSF
   endpoint may require introspection to be enabled.

Note that a **wrong `aud` is _not_ a cause here** — Keycloak's SSF gate never
inspects the audience. Chasing `aud` on this endpoint is a dead end.

#### Where to get the `access_token` from Keycloak

Keycloak's SSF transmitter is **experimental and off by default**. Start the
server with the feature enabled first, or none of the SSF endpoints exist:

```
kc.sh start-dev --feature-ssf=enabled
```

Then, in the admin console, in the *same realm* as the transmitter (e.g.
`geointdemo`):

1. **Realm settings →** turn the **SSF Transmitter** toggle **on**. This sets
   the `ssf.transmitterEnabled` realm attribute and activates the per-realm
   SSF endpoints (metadata, stream management, JWKS). Without it, discovery
   may still 404 or the stream endpoints won't be routed.
2. **Clients → Create client.** Client ID e.g. `ssf-bridge`, type *OpenID
   Connect*. **Next.**
3. Turn **Client authentication → On** (confidential client; a public client
   cannot use client credentials).
4. Under **Authentication flow**, tick **Service accounts roles** and untick
   *Standard flow* / *Direct access grants* — the bridge is a machine client.
   **Save.** This step is **mandatory**, not stylistic: Keycloak's SSF gate
   requires the token to be this client's own service-account token, so the
   client-credentials grant must be available on the *same* client you enable
   SSF on below.
5. On the client's **SSF tab**: enable **SSF**, set **Default Subjects** to
   `ALL`, set an **Audience**, and tick **Push** as a supported delivery
   method. This is what writes `ssf.enabled=true`.
6. Still on the **SSF tab**, add the bridge's `/events` URL to **Valid push
   URLs** (`ssf.validPushUrls`). Keycloak's SSRF gate **rejects PUSH stream
   creation with a 400 when this list is empty** — it is not optional. Entries
   are exact-match or trailing-`*` (e.g. `https://ssf-bridge.f5demos.com/*`),
   a bare `*` is ignored, and the URL must be `https` with a non-private host
   unless the operator set `allow-insecure-push-targets`.
7. **Client scopes → Add client scope →** add **`ssf.read`** and
   **`ssf.manage`** (Optional is what the Keycloak docs use).
8. **Credentials tab → copy the Client secret.**

**Then mint the token** with the helper. It requests
`scope=ssf.read ssf.manage` by default and warns if Keycloak dropped either
one:

```
python tools/get_keycloak_token.py \
  --issuer https://keycloak.f5demos.com:30182/realms/geointdemo \
  --client-id ssf-bridge --client-secret <secret> --insecure
```

It prints the token, flags an expired/opaque/wrong-audience token, warns when
`ssf.read` or `ssf.manage` is missing from the granted scopes, and emits a
ready-to-paste `/admin/transmitters/discover` body. Use `--quiet` for just the
token, and `--scope` to override the requested scopes.

Equivalent raw call, from inside the pod (note the `scope` parameter — omitting
it is the usual reason the resulting token gets a 401 at `/streams`):

```
kubectl exec -n ssf-bridge deploy/ssf-apm-bridge -- python -c "import httpx; \
r=httpx.post('https://keycloak.f5demos.com:30182/realms/geointdemo/protocol/openid-connect/token', \
data={'grant_type':'client_credentials','client_id':'<id>','client_secret':'<secret>', \
'scope':'ssf.read ssf.manage'}, \
verify=False, timeout=10); print(r.status_code, r.text[:400])"
```

> The token is short-lived (60–300s by default). Mint it **immediately**
> before calling `/discover`, or raise *Advanced → Access Token Lifespan* on
> the client. The bridge stores this token and reuses it for stream
> management and polling, so a longer lifespan (or a client whose token you
> can refresh) is preferable for anything beyond a one-shot demo.

### Keycloak SSF compatibility

Checked against Keycloak's [experimental SSF transmitter](https://www.keycloak.org/2026/07/experimental-ssf-support).

| What the bridge sends | Keycloak expects | Status |
|---|---|---|
| `GET /.well-known/ssf-configuration/realms/{realm}`, falling back to `…/realms/{realm}/.well-known/ssf-configuration` | Both shapes are published and return the same document. The host-rooted (RFC 8615) form is only served when `KC_HTTP_RELATIVE_PATH` is empty. | ✅ tries both |
| `POST` to the advertised `configuration_endpoint` | `POST /realms/{realm}/ssf/transmitter/streams` | ✅ endpoint is taken from metadata, not hardcoded |
| `delivery.method` = `urn:ietf:rfc:8935` | Accepts `urn:ietf:rfc:8935` and the legacy `https://schemas.openid.net/secevent/risc/delivery-method/push`; both collapse to the `push` family | ✅ |
| `delivery.endpoint_url`, `events_requested`, `description` | Receiver-writable fields | ✅ |
| No `stream_id` / `iss` / `aud` / `events_supported` in the request | Those are transmitter-stamped; supplying them is a **400** | ✅ never sent |
| `Authorization: Bearer <token>` | Token must carry `ssf.read ssf.manage` **and** be the receiver client's own service-account token | ⚠️ the bridge forwards whatever token you pass — mint it with `client_credentials` on the receiver client itself |

Keycloak-side prerequisites the bridge cannot satisfy for you:

- The server runs with `--feature-ssf=enabled` and the realm's **SSF
  Transmitter** toggle is on. (If either is off the whole `/ssf/transmitter`
  subtree is absent, which surfaces as a **404**, not a 401 — the resource
  locator returns `null` before any token is examined.)
- The token is the receiver client's **own service-account** token, unless
  `ssf.requireServiceAccount=false` is set on that client.
- The receiver client has `ssf.enabled=true` and a **non-empty**
  `ssf.validPushUrls` covering the bridge's `/events` URL — Keycloak's SSRF
  gate rejects PUSH with a 400 when that allow-list is empty, and the URL must
  be `https` with a non-private host.
- `push` is permitted by `ssf.allowedDeliveryMethods` (absent ⇒ both allowed).

Two behaviours worth knowing about:

- **One stream per receiver client.** A second create returns **409**. If
  `/discover` half-succeeded, delete the existing stream before retrying —
  the bridge reports this explicitly rather than as a generic failure.
- **Keycloak stamps `aud` itself.** `/discover` already prefers the `aud` the
  transmitter returns in the stream object over its own default guess, so SET
  audience validation lines up without extra configuration.

### Self-signed transmitters: `verify_tls`

Both `POST /admin/transmitters` and `POST /admin/transmitters/discover`
accept an optional `verify_tls` boolean. Setting it to `false` skips
certificate **and hostname** verification for *every* outbound call to that
transmitter — discovery, stream management, JWKS, and polling:

```jsonc
{
  "issuer_or_config_url": "https://keycloak.f5demos.com:30182/realms/geointdemo",
  "access_token": "...",
  "events_requested": [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  ],
  "verify_tls": false
}
```

The flag is **persisted on the registered transmitter**, which matters
because the JWKS fetch happens later during SET verification, not during the
discovery call — without persistence, discovery would succeed and then every
SET from that transmitter would fail to verify. Omit the field to inherit the
`SSF_VERIFY_TLS` setting (default `true`). Each use logs a
`tls_verification_disabled` warning.

> **Security:** turning verification off means anyone able to intercept the
> connection can impersonate the transmitter and inject
> `session-revoked` events, i.e. deny service to arbitrary users. It also
> will *not* fix a `RemoteProtocolError` — that failure happens before TLS.
> Prefer `CA_BUNDLE_PATH` with your internal CA; treat `verify_tls: false`
> as a lab-only shortcut.

> **Note:** `tools/mock_transmitter.py` does **not** serve
> `/.well-known/ssf-configuration` (only `jwks.json`, bound to `127.0.0.1`),
> so `/discover` cannot work against it. Use `POST /admin/transmitters`.

> **Note:** the transmitter registry is in-process
> (`app/ssf/registry.py`), so with `replicas: 2` only the pod that served
> the `/discover` call knows the transmitter, and SETs arriving at the other
> pod fail with `UnknownIssuer`. Scale to one replica for lab testing until
> the registry is backed by Redis.

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
| `verification` | SSF | informational | Stream health-check echo; acknowledged and logged, no enforcement. |

`app/enforcement/router.py` is the source of truth (`EVENT_PATHS`) --
these are judgment calls, not spec requirements, and are meant to be
edited for your risk tolerance.

A single SET may carry several events (RFC 8417 §2). Every event in the
token is dispatched independently, and the reported path is the most
severe one taken (fast > continuous > informational).

### SET freshness and replay

SETs deliberately carry no `exp`, so `iat` age is the only bound on how
long a captured token remains useful: anything older than
`SET_MAX_AGE_SECONDS` (default 900) is rejected, and future-dated tokens
are allowed only within `SET_CLOCK_SKEW_SECONDS` (default 120). Keep
`REPLAY_JTI_TTL_SECONDS >= SET_MAX_AGE_SECONDS` so a SET cannot become
replayable again once its `jti` ages out of the replay guard.

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
- [RFC 8935 — Push-Based SET Delivery](https://www.rfc-editor.org/rfc/rfc8935)
- [Keycloak: Experimental Shared Signals Framework support](https://www.keycloak.org/2026/07/experimental-ssf-support)
  — the transmitter this bridge is tested against; see the compatibility
  notes below.
- [F5 iRules APM command reference](https://clouddocs.f5.com/api/irules/APM.html)
- [F5 tmsh `apm session` reference](https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/apm/apm_session.html)
- [BIG-IP APM OAuth Client and Resource Server](https://techdocs.f5.com/en-us/bigip-17-1-0/big-ip-access-policy-manager-oauth-configuration/apm-oauth-client-and-resource-server.html)
