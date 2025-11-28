#!/bin/bash
#
# Auto-remediation script for container security issues

set -e

SCAN_RESULTS="$1"
ACTION="${2:-quarantine}"

log_message() {
    echo "$(date): $1" >> /var/log/container-remediation.log
}

quarantine_image() {
    local image="$1"
    local reason="$2"
    
    log_message "Quarantining image $image: $reason"
    
    # Tag image as quarantined
    docker tag "$image" "${image}-quarantined-$(date +%Y%m%d)"
    
    # Stop running containers using this image
    local containers=$(docker ps --filter "ancestor=$image" -q)
    
    if [ -n "$containers" ]; then
        log_message "Stopping containers using quarantined image: $containers"
        docker stop $containers
    fi
}

rollback_deployment() {
    local namespace="$1"
    local deployment="$2"
    local image="$3"
    
    log_message "Rolling back deployment $deployment in namespace $namespace"
    
    if kubectl rollout undo deployment/"$deployment" -n "$namespace"; then
        log_message "Successfully rolled back $deployment"
    else
        log_message "ERROR: Failed to roll back $deployment"
        return 1
    fi
}

notify_security_team() {
    local image="$1"
    local risk_score="$2"
    local critical_count="$3"
    
    local subject="CRITICAL: Security issue detected in $image"
    local body="Image: $image
Risk Score: $risk_score
Critical Vulnerabilities: $critical_count
Time: $(date)
    
Immediate action required."
    
    # Send notification (configure with your notification system)
    echo "$body" | mail -s "$subject" security-team@company.com
}

main() {
    if [ -z "$SCAN_RESULTS" ] || [ ! -f "$SCAN_RESULTS" ]; then
        echo "Usage: $0 <scan-results.json> [quarantine|rollback|notify]"
        exit 1
    fi
    
    local image=$(jq -r '.image' "$SCAN_RESULTS")
    local risk_score=$(jq -r '.risk_score' "$SCAN_RESULTS")
    local critical_count=$(jq -r '.vulnerabilities.critical' "$SCAN_RESULTS")
    
    log_message "Processing remediation for image: $image (risk: $risk_score, critical: $critical_count)"
    
    case "$ACTION" in
        "quarantine")
            if [ "$risk_score" -gt 80 ] || [ "$critical_count" -gt 0 ]; then
                quarantine_image "$image" "Risk score $risk_score with $critical_count critical vulnerabilities"
            fi
            ;;
        "rollback")
            if [ "$risk_score" -gt 50 ]; then
                # Extract deployment info from image tags or metadata
                local namespace="default"
                local deployment=$(echo "$image" | cut -d':' -f1 | cut -d'/' -f2)
                rollback_deployment "$namespace" "$deployment" "$image"
            fi
            ;;
        "notify")
            if [ "$risk_score" -gt 70 ] || [ "$critical_count" -gt 0 ]; then
                notify_security_team "$image" "$risk_score" "$critical_count"
            fi
            ;;
        *)
            echo "Unknown action: $ACTION"
            exit 1
            ;;
    esac
}

main "$@"
