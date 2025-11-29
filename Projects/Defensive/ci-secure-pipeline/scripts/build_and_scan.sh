#!/bin/bash
set -euo pipefail

# Configuration
IMAGE_NAME="${1:-ghcr.io/$(git config user.name)/secure-ci-cd-app:latest}"
SCAN_RESULTS_DIR="${2:-./scan-results}"
TRIVY_CACHE_DIR="${3:-./.trivycache}"
POLICY_FILE="${4:-./policy/security-policy.yml}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create directories
mkdir -p "$SCAN_RESULTS_DIR" "$TRIVY_CACHE_DIR"

log() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

check_dependencies() {
    local deps=("docker" "trivy" "cosign")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency $dep not found"
            return 1
        fi
    done
    log "All dependencies verified"
}

build_image() {
    log "Building Docker image: $IMAGE_NAME"
    if ! docker build -t "$IMAGE_NAME" -f src/Dockerfile .; then
        error "Docker build failed"
        return 1
    fi
    log "Docker build completed successfully"
}

run_vulnerability_scan() {
    log "Running vulnerability scan on $IMAGE_NAME"
    
    # Run Trivy scan and capture exit code
    trivy image \
        --cache-dir "$TRIVY_CACHE_DIR" \
        --format json \
        --output "$SCAN_RESULTS_DIR/trivy-scan.json" \
        --severity HIGH,CRITICAL \
        "$IMAGE_NAME" || true  # Don't fail immediately, we'll check results
    
    # Also create human-readable report
    trivy image \
        --cache-dir "$TRIVY_CACHE_DIR" \
        --format table \
        --output "$SCAN_RESULTS_DIR/trivy-scan.txt" \
        --severity HIGH,CRITICAL \
        "$IMAGE_NAME" || true
    
    log "Vulnerability scan completed"
}

check_scan_results() {
    local scan_file="$SCAN_RESULTS_DIR/trivy-scan.json"
    
    if [[ ! -f "$scan_file" ]]; then
        error "Scan results file not found: $scan_file"
        return 1
    fi
    
    # Parse JSON and check for critical vulnerabilities
    local critical_count
    critical_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$scan_file")
    
    local high_count
    high_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$scan_file")
    
    log "Scan results - CRITICAL: $critical_count, HIGH: $high_count"
    
    # Check against policy
    if [[ "$critical_count" -gt 0 ]]; then
        error "Policy violation: $critical_count CRITICAL vulnerabilities found"
        return 1
    fi
    
    if [[ "$high_count" -gt 5 ]]; then
        warn "High vulnerability count: $high_count HIGH severity issues"
        # Don't fail for high severity, just warn
    fi
    
    log "Vulnerability scan passed policy checks"
    return 0
}

generate_sbom() {
    log "Generating Software Bill of Materials (SBOM)"
    
    trivy image \
        --cache-dir "$TRIVY_CACHE_DIR" \
        --format cyclonedx \
        --output "$SCAN_RESULTS_DIR/sbom.json" \
        "$IMAGE_NAME"
    
    log "SBOM generated: $SCAN_RESULTS_DIR/sbom.json"
}

main() {
    log "Starting secure build and scan process"
    
    # Validate dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Build image
    if ! build_image; then
        exit 1
    fi
    
    # Run security scan
    run_vulnerability_scan
    
    # Check scan results against policy
    if ! check_scan_results; then
        error "Build failed due to policy violations"
        exit 1
    fi
    
    # Generate SBOM
    generate_sbom
    
    log "Build and scan process completed successfully"
    echo "{\"status\": \"success\", \"image\": \"$IMAGE_NAME\", \"scan_results\": \"$SCAN_RESULTS_DIR/trivy-scan.json\"}" | jq .
}

main "$@"
