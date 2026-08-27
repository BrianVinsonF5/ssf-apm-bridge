# Automated Deployment Script for SSF-APM Bridge on Kubernetes (PowerShell)
[CmdletBinding()]
param (
    [string]$ImageName = "ssf-apm-bridge:latest",
    [string]$Namespace = "ssf-bridge",
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"

Write-Host "==> Deploying SSF-APM Bridge to Kubernetes namespace '$Namespace'..." -ForegroundColor Green

# 1. Check prerequisites
if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Error "kubectl is not installed or not in PATH."
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker is not installed or not in PATH."
    exit 1
}

# 2. Build Docker Image
Write-Host "==> Building Docker image '$ImageName'..." -ForegroundColor Cyan
docker build -t $ImageName .
if ($LASTEXITCODE -ne 0) { Write-Error "Docker build failed."; exit 1 }

# 3. Handle Minikube / Kind if detected
if (Get-Command minikube -ErrorAction SilentlyContinue) {
    $miniStatus = minikube status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "==> Loading image into Minikube..." -ForegroundColor Cyan
        minikube image load $ImageName
    }
} elseif (Get-Command kind -ErrorAction SilentlyContinue) {
    $kindClusters = kind get clusters 2>&1
    if ($kindClusters -and $kindClusters -notmatch "No kind clusters found") {
        Write-Host "==> Loading image into Kind..." -ForegroundColor Cyan
        kind load docker-image $ImageName
    }
}

# 4. Apply Namespace
Write-Host "==> Applying Namespace..." -ForegroundColor Cyan
kubectl apply -f k8s/00-namespace.yaml

# 5. Apply ConfigMap
Write-Host "==> Applying ConfigMap..." -ForegroundColor Cyan
kubectl apply -f k8s/01-configmap.yaml

# 6. Apply Secret
if (Test-Path $EnvFile) {
    Write-Host "==> Creating Secret from $EnvFile..." -ForegroundColor Cyan
    $adminKey = "change-me-to-a-long-random-value"
    $bigipUser = "ssf-bridge-svc"
    $bigipPass = "change-me"

    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match "^ADMIN_API_KEY=(.*)$") { $adminKey = $matches[1] }
        if ($_ -match "^BIGIP_USERNAME=(.*)$") { $bigipUser = $matches[1] }
        if ($_ -match "^BIGIP_PASSWORD=(.*)$") { $bigipPass = $matches[1] }
    }

    kubectl create secret generic ssf-bridge-secrets `
        --namespace=$Namespace `
        --from-literal=ADMIN_API_KEY=$adminKey `
        --from-literal=BIGIP_USERNAME=$bigipUser `
        --from-literal=BIGIP_PASSWORD=$bigipPass `
        --dry-run=client -o yaml | kubectl apply -f -
} else {
    Write-Host "==> Applying secret template k8s/02-secret.yaml..." -ForegroundColor Cyan
    kubectl apply -f k8s/02-secret.yaml
}

# 7. Apply Internal CA Trust ConfigMap & cert-manager resources
if (Test-Path "k8s/08-internal-ca-configmap.yaml") {
    Write-Host "==> Applying Internal CA Bundle ConfigMap..." -ForegroundColor Cyan
    kubectl apply -f k8s/08-internal-ca-configmap.yaml
}

if (Test-Path "k8s/07-cert-manager.yaml") {
    Write-Host "==> Applying cert-manager resources..." -ForegroundColor Cyan
    kubectl apply -f k8s/07-cert-manager.yaml -ErrorAction SilentlyContinue
}

# 8. Apply Redis Caching Backend
Write-Host "==> Applying Redis backend..." -ForegroundColor Cyan
kubectl apply -f k8s/03-redis.yaml

# 9. Apply Deployment & Service
Write-Host "==> Applying SSF-APM Bridge Deployment and Service..." -ForegroundColor Cyan
kubectl apply -f k8s/04-deployment.yaml
kubectl apply -f k8s/05-service.yaml

# 10. Apply Ingress
if (Test-Path "k8s/06-ingress.yaml") {
    Write-Host "==> Applying Ingress..." -ForegroundColor Cyan
    kubectl apply -f k8s/06-ingress.yaml -ErrorAction SilentlyContinue
}

# 10. Wait for Rollout
Write-Host "==> Waiting for deployment rollout..." -ForegroundColor Cyan
kubectl rollout status deployment/ssf-apm-bridge -n $Namespace --timeout=120s

Write-Host "==> SSF-APM Bridge successfully deployed!" -ForegroundColor Green
Write-Host "    Check status: kubectl get pods -n $Namespace" -ForegroundColor Yellow
