"""The Kubernetes TLS wiring, asserted as a unit.

Inbound TLS is spread across five manifests -- a cert-manager `Certificate`,
the secret it populates, the volume that mounts it, the paths uvicorn reads
it from, and the Ingress that re-uses it. Each file is individually
plausible, so a mismatch between any two of them only surfaces in-cluster:
a pod stuck in `ContainerCreating`, a crash loop on a missing keypair, or an
nginx 502 that looks nothing like a certificate problem.

These are pure YAML assertions -- no cluster, no kubectl. They exist because
the manifests were shipped once with an unresolved merge conflict in
01-configmap.yaml, which made `kubectl apply -f k8s/` fail outright and
which nothing in the suite would have caught.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

K8S = Path(__file__).resolve().parent.parent / "k8s"

# The lab CA that already exists in the cluster; this repo does not create it.
ISSUER = {"name": "lab-ca-issuer", "kind": "ClusterIssuer"}
TLS_SECRET = "ssf-bridge-tls"


def _load(name: str) -> dict:
    with open(K8S / name, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def configmap() -> dict:
    return _load("01-configmap.yaml")


@pytest.fixture(scope="module")
def deployment() -> dict:
    return _load("04-deployment.yaml")


@pytest.fixture(scope="module")
def service() -> dict:
    return _load("05-service.yaml")


@pytest.fixture(scope="module")
def ingress() -> dict:
    return _load("06-ingress.yaml")


@pytest.fixture(scope="module")
def certificate() -> dict:
    return _load("07-cert-manager.yaml")


@pytest.fixture(scope="module")
def container(deployment) -> dict:
    return deployment["spec"]["template"]["spec"]["containers"][0]


# --- every manifest must actually parse -------------------------------


@pytest.mark.parametrize("path", sorted(K8S.glob("*.yaml")), ids=lambda p: p.name)
def test_manifest_is_valid_yaml(path):
    """A merge conflict shipped in 01-configmap.yaml once already, and
    `kubectl apply -f k8s/` fails on the whole directory, not just the bad
    file -- so one conflicted manifest blocks the entire deployment."""
    with open(path, encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]
    assert docs, f"{path.name} parsed to nothing"
    for doc in docs:
        assert doc.get("kind"), f"{path.name} has a document without a kind"


@pytest.mark.parametrize("path", sorted(K8S.glob("*.yaml")), ids=lambda p: p.name)
def test_no_merge_conflict_markers(path):
    text = path.read_text(encoding="utf-8")
    for marker in ("<<<<<<<", ">>>>>>>"):
        assert marker not in text, f"{path.name} still contains {marker}"


# --- issuance ---------------------------------------------------------


def test_certificate_comes_from_the_cluster_issuer(certificate):
    assert certificate["kind"] == "Certificate"
    assert certificate["spec"]["issuerRef"] == ISSUER


def test_certificate_is_a_server_cert(certificate):
    """nginx verifies the upstream (proxy-ssl-verify: on) and the BIG-IP
    checks EKU, so a leaf without serverAuth fails only from those callers
    -- never from a local curl."""
    spec = certificate["spec"]
    assert spec["isCA"] is False
    assert "server auth" in spec["usages"]


def test_private_key_rotates_on_renewal(certificate):
    """cert-manager's default is 'Never', which re-signs the original key
    for the life of the deployment so a leak is never aged out."""
    assert certificate["spec"]["privateKey"]["rotationPolicy"] == "Always"


def test_common_name_is_also_a_san(certificate):
    """CN alone has been ignored by browsers and Go's TLS stack for years."""
    assert certificate["spec"]["commonName"] in certificate["spec"]["dnsNames"]


def test_in_cluster_service_names_are_sans(certificate, service):
    """Hostname verification runs against the name the caller dialled, not
    the FQDN, so every DNS form cluster search paths resolve must be a SAN."""
    svc = service["metadata"]["name"]
    ns = service["metadata"]["namespace"]
    sans = certificate["spec"]["dnsNames"]
    for form in (f"{svc}.{ns}.svc.cluster.local", f"{svc}.{ns}.svc", f"{svc}.{ns}", svc):
        assert form in sans, f"{form} is not a SAN"


# --- the keypair's path from Certificate to uvicorn -------------------


def _tls_mount(container: dict) -> dict:
    return next(m for m in container["volumeMounts"] if m["name"] == "tls-volume")


def _tls_volume(deployment: dict) -> dict:
    volumes = deployment["spec"]["template"]["spec"]["volumes"]
    return next(v for v in volumes if v["name"] == "tls-volume")


def test_deployment_mounts_the_secret_the_certificate_populates(
    deployment, certificate
):
    assert certificate["spec"]["secretName"] == TLS_SECRET
    assert _tls_volume(deployment)["secret"]["secretName"] == TLS_SECRET


def test_configured_paths_point_into_the_mount(configmap, container):
    """TLS_CERT_FILE/TLS_KEY_FILE resolving anywhere else is a crash loop:
    app/__main__.py exits non-zero rather than downgrading to plaintext."""
    mount_path = _tls_mount(container)["mountPath"]
    assert configmap["data"]["TLS_CERT_FILE"] == f"{mount_path}/tls.crt"
    assert configmap["data"]["TLS_KEY_FILE"] == f"{mount_path}/tls.key"


def test_keypair_is_not_mounted_with_subpath(container):
    """subPath mounts are never refreshed by the kubelet, so a renewed
    certificate would sit in the secret and never reach the container."""
    assert "subPath" not in _tls_mount(container)


def test_tls_secret_is_not_optional(deployment):
    """optional: true would let the pod start without a keypair, and the
    container would then exit -- a crash loop instead of a clear
    'secret not found' scheduling event."""
    assert _tls_volume(deployment)["secret"]["optional"] is False


def test_renewal_triggers_a_restart(deployment):
    """uvicorn reads the keypair only at start-up; without this the pod
    serves the superseded leaf until someone notices."""
    annotations = deployment["metadata"]["annotations"]
    assert annotations["reloader.stakater.com/auto"] == "true"
    assert annotations["secret.reloader.stakater.com/reload"] == TLS_SECRET


# --- the listener is actually https -----------------------------------


def test_port_is_consistent_end_to_end(configmap, container, service):
    port = container["ports"][0]["containerPort"]
    assert int(configmap["data"]["PORT"]) == port
    assert service["spec"]["ports"][0]["targetPort"] == port


@pytest.mark.parametrize("probe", ["livenessProbe", "readinessProbe"])
def test_probes_speak_https(container, probe):
    """A plaintext GET against a TLS listener fails every probe and
    crash-loops the pod."""
    assert container[probe]["httpGet"]["scheme"] == "HTTPS"


# --- the Ingress ------------------------------------------------------


def test_ingress_reuses_the_certificates_secret(ingress, certificate):
    assert ingress["spec"]["tls"][0]["secretName"] == certificate["spec"]["secretName"]


def test_ingress_does_not_ask_the_shim_for_a_second_certificate(ingress):
    """cert-manager requires each Ingress to own a unique tls.secretName.
    Annotating an Ingress that points at a secret an explicit Certificate
    already manages yields two Certificates overwriting one another."""
    assert "cert-manager.io/cluster-issuer" not in ingress["metadata"]["annotations"]
    assert "cert-manager.io/issuer" not in ingress["metadata"]["annotations"]


def test_ingress_talks_https_to_the_pod(ingress, certificate):
    """The pod terminates TLS, so a cleartext upstream connection is a 502
    on every route -- and the verified name has to be a SAN."""
    annotations = ingress["metadata"]["annotations"]
    assert annotations["nginx.ingress.kubernetes.io/backend-protocol"] == "HTTPS"
    assert annotations["nginx.ingress.kubernetes.io/proxy-ssl-verify"] == "on"
    assert (
        annotations["nginx.ingress.kubernetes.io/proxy-ssl-name"]
        in certificate["spec"]["dnsNames"]
    )


def test_ingress_host_matches_the_certificate(ingress, certificate):
    host = ingress["spec"]["rules"][0]["host"]
    assert host in certificate["spec"]["dnsNames"]
    assert ingress["spec"]["tls"][0]["hosts"] == [host]


def test_receiver_base_url_is_a_name_on_the_certificate(configmap, certificate):
    """Keycloak validates the bridge's cert when delivering pushes to
    ${RECEIVER_BASE_URL}/events, so a host that isn't a SAN turns an
    allow-list problem into a handshake failure at delivery time."""
    base = configmap["data"]["RECEIVER_BASE_URL"]
    assert base.startswith("https://"), "Keycloak refuses non-https push targets"
    host = base.removeprefix("https://").split("/")[0].split(":")[0]
    assert host in certificate["spec"]["dnsNames"]


# --- namespacing ------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "01-configmap.yaml",
        "04-deployment.yaml",
        "05-service.yaml",
        "06-ingress.yaml",
        "07-cert-manager.yaml",
    ],
)
def test_resources_share_the_namespace(name):
    """A Certificate's secret is only mountable from its own namespace."""
    assert _load(name)["metadata"]["namespace"] == "ssf-bridge"
