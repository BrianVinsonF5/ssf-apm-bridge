#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Automated Deployment Script for SSF-APM Bridge on Kubernetes
# ------------------------------------------------------------------------------

IMAGE_NAME="${IMAGE_NAME:-ghcr.io/brianvinsonf5/ssf-apm-bridge:latest}"
NAMESPACE="${NAMESPACE:-ssf-bridge}"
ENV_FILE="${ENV_FILE:-.env}"
PUSH_IMAGE="${PUSH_IMAGE:-false}"

echo "==> Deploying SSF-APM Bridge to Kubernetes namespace '${NAMESPACE}'..."

# 1. Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl command line tool is not installed or not in PATH." >&2
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "Error: docker is not installed or not in PATH." >&2
    exit 1
fi

# 2. Build Docker Image
echo "==> Building Docker image '${IMAGE_NAME}'..."
docker build -t "${IMAGE_NAME}" .

# 3. Optional: Push Docker Image to Container Registry
if [ "${PUSH_IMAGE}" = "true" ]; then
    echo "==> Pushing Docker image '${IMAGE_NAME}' to registry..."
    docker push "${IMAGE_NAME}"
fi

# 4. Handle Minikube / Kind if detected
if command -v minikube &> /dev/null && minikube status &> /dev/null; then
    echo "==> Loading image into Minikube..."
    minikube image load "${IMAGE_NAME}"
elif command -v kind &> /dev/null && kind get clusters 2>/dev/null | grep -q .; then
    echo "==> Loading image into Kind..."
    kind load docker-image "${IMAGE_NAME}"
fi

# 4. Apply Namespace
echo "==> Applying Namespace..."
kubectl apply -f k8s/00-namespace.yaml

# 5. Apply ConfigMap
echo "==> Applying ConfigMap..."
kubectl apply -f k8s/01-configmap.yaml

# 6. Apply Secret (Read from .env if available, otherwise apply template)
if [ -f "${ENV_FILE}" ]; then
    echo "==> Creating Secret from ${ENV_FILE} file..."
    ADMIN_KEY=$(grep '^ADMIN_API_KEY=' "${ENV_FILE}" | cut -d '=' -f2- || echo "change-me-to-a-long-random-value")
    BIGIP_USER=$(grep '^BIGIP_USERNAME=' "${ENV_FILE}" | cut -d '=' -f2- || echo "ssf-bridge-svc")
    BIGIP_PASS=$(grep '^BIGIP_PASSWORD=' "${ENV_FILE}" | cut -d '=' -f2- || echo "change-me")

    kubectl create secret generic ssf-bridge-secrets \
        --namespace="${NAMESPACE}" \
        --from-literal=ADMIN_API_KEY="${ADMIN_KEY}" \
        --from-literal=BIGIP_USERNAME="${BIGIP_USER}" \
        --from-literal=BIGIP_PASSWORD="${BIGIP_PASS}" \
        --dry-run=client -o yaml | kubectl apply -f -
else
    echo "==> Applying secret template k8s/02-secret.yaml..."
    kubectl apply -f k8s/02-secret.yaml
fi

# 7. Apply Internal CA Trust ConfigMap & cert-manager resources
echo "==> Applying Internal CA Bundle ConfigMap..."
if [ -f k8s/08-internal-ca-configmap.yaml ]; then
    kubectl apply -f k8s/08-internal-ca-configmap.yaml
fi

echo "==> Applying cert-manager resources..."
if [ -f k8s/07-cert-manager.yaml ]; then
    kubectl apply -f k8s/07-cert-manager.yaml || echo "Warning: cert-manager CRDs not present, skipping cert-manager Issuer/Certificate."
fi

# 8. Apply Redis Caching Backend
echo "==> Applying Redis backend..."
kubectl apply -f k8s/03-redis.yaml

# 9. Apply Deployment & Service
echo "==> Applying SSF-APM Bridge Deployment and Service..."
kubectl apply -f k8s/04-deployment.yaml
kubectl apply -f k8s/05-service.yaml

# 10. Apply Ingress (optional)
if [ -f k8s/06-ingress.yaml ]; then
    echo "==> Applying Ingress..."
    kubectl apply -f k8s/06-ingress.yaml || echo "Warning: Ingress creation failed or ingress-controller not present, skipping."
fi

# 10. Wait for Rollout
echo "==> Waiting for deployment rollout..."
kubectl rollout status deployment/ssf-apm-bridge -n "${NAMESPACE}" --timeout=120s

echo "==> SSF-APM Bridge successfully deployed!"
echo "    Check status: kubectl get pods -n ${NAMESPACE}"

# 11. Report the external NodePort address so the REST client / BIG-IP can be
# pointed at the bridge without hunting through kubectl output.
NODE_PORT="$(kubectl get svc ssf-apm-bridge-service -n "${NAMESPACE}" \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)"
if [ -n "${NODE_PORT}" ]; then
    NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null || true)"
    if [ -z "${NODE_IP}" ]; then
        NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)"
        [ -n "${NODE_IP}" ] && echo "    Note: no node ExternalIP found; showing InternalIP (may not be reachable from the BIG-IP)."
    fi
    echo "    NodePort URL: http://${NODE_IP:-<node-ip>}:${NODE_PORT}"
    echo "    Health check: curl http://${NODE_IP:-<node-ip>}:${NODE_PORT}/health"
    echo "    Ensure the node firewall/security group allows inbound TCP ${NODE_PORT}."
fi
