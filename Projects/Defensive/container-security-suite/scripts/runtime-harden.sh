#!/bin/bash
#
# Container Runtime Hardening Script
# Applies security best practices to running containers

set -e

CONTAINER_ID="$1"
LOG_FILE="/var/log/container-hardening.log"

log_message() {
    echo "$(date): $1" >> "$LOG_FILE"
}

validate_container() {
    if [ -z "$CONTAINER_ID" ]; then
        echo "Usage: $0 <container-id>"
        exit 1
    fi
    
    if ! docker inspect "$CONTAINER_ID" > /dev/null 2>&1; then
        echo "Container $CONTAINER_ID not found"
        exit 1
    fi
}

enforce_non_root() {
    log_message "Enforcing non-root user for $CONTAINER_ID"
    
    local current_user=$(docker exec "$CONTAINER_ID" whoami 2>/dev/null || echo "root")
    
    if [ "$current_user" = "root" ]; then
        log_message "WARNING: Container $CONTAINER_ID running as root"
        # In production, you might want to restart with non-root user
        return 1
    fi
}

drop_capabilities() {
    log_message "Dropping dangerous capabilities for $CONTAINER_ID"
    
    # List of capabilities to drop
    local dangerous_caps=(
        "CAP_SYS_ADMIN"
        "CAP_NET_RAW" 
        "CAP_SYS_MODULE"
        "CAP_SYS_RAWIO"
        "CAP_SYS_PACCT"
        "CAP_SYS_NICE"
        "CAP_SYS_RESOURCE"
        "CAP_SYS_TIME"
        "CAP_SYS_TTY_CONFIG"
        "CAP_AUDIT_CONTROL"
        "CAP_MAC_OVERRIDE"
        "CAP_MAC_ADMIN"
        "CAP_NET_ADMIN"
        "CAP_SYS_BOOT"
        "CAP_SYS_CHROOT"
        "CAP_SETFCAP"
        "CAP_SETPCAP"
        "CAP_LINUX_IMMUTABLE"
        "CAP_IPC_LOCK"
        "CAP_IPC_OWNER"
    )
    
    for cap in "${dangerous_caps[@]}"; do
        if docker update --cap-drop "$cap" "$CONTAINER_ID" > /dev/null 2>&1; then
            log_message "Dropped capability: $cap"
        fi
    done
}

set_readonly_rootfs() {
    log_message "Setting read-only root filesystem for $CONTAINER_ID"
    
    if docker update --read-only "$CONTAINER_ID" > /dev/null 2>&1; then
        log_message "Successfully set read-only root filesystem"
    else
        log_message "WARNING: Could not set read-only rootfs - container may need writable files"
    fi
}

disable_privileged() {
    local privileged=$(docker inspect --format='{{.HostConfig.Privileged}}' "$CONTAINER_ID")
    
    if [ "$privileged" = "true" ]; then
        log_message "CRITICAL: Container $CONTAINER_ID is running in privileged mode"
        # In production, you might want to stop the container
        return 1
    fi
}

main() {
    log_message "Starting runtime hardening for container: $CONTAINER_ID"
    
    validate_container
    disable_privileged
    enforce_non_root
    drop_capabilities
    set_readonly_rootfs
    
    log_message "Completed runtime hardening for container: $CONTAINER_ID"
}

main "$@"
