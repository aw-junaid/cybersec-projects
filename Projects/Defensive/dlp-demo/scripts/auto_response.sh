#!/bin/bash
#
# DLP Auto-Response Script - Lab Use Only
# WARNING: Never run in production without modification and testing
#

set -e

# Safety checks
if [ "$DLP_LAB_MODE" != "1" ]; then
    echo "ERROR: DLP_LAB_MODE not set to 1. Aborting for safety."
    exit 2
fi

# Default values
ALERT_FILE=""
ENABLE_ACTIONS=false
BLOCKLIST_FILE="/tmp/dlp_blocklist.txt"
LOG_FILE="/tmp/dlp_response.log"
MOCK_API_URL="http://localhost:8080/mock"

# Usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "DLP Auto-Response - Lab Use Only"
    echo ""
    echo "Options:"
    echo "  -a, --alert-file FILE    JSON alert file to process"
    echo "  -e, --enable-actions     Enable destructive actions (requires confirmation)"
    echo "  -b, --blocklist FILE     Blocklist file path (default: $BLOCKLIST_FILE)"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Safety Notice: This script is for lab demonstration only."
    echo "Never use in production without thorough testing and approval."
}

# Log function
log() {
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $1" >> "$LOG_FILE"
    echo "$1"
}

# Safety confirmation
confirm_actions() {
    if [ "$ENABLE_ACTIONS" = true ]; then
        read -p "WARNING: Destructive actions enabled. Type 'CONFIRM' to proceed: " response
        if [ "$response" != "CONFIRM" ]; then
            echo "Confirmation failed. Aborting."
            exit 1
        fi
    fi
}

# Parse alert JSON
parse_alert() {
    if [ ! -f "$ALERT_FILE" ]; then
        log "ERROR: Alert file not found: $ALERT_FILE"
        exit 1
    fi

    # Extract alert fields using jq
    ALERT_ID=$(jq -r '.alert_id' "$ALERT_FILE")
    SOURCE_IP=$(jq -r '.source.ip' "$ALERT_FILE")
    DEST_IP=$(jq -r '.destination.ip' "$ALERT_FILE")
    DEST_HOST=$(jq -r '.destination.host' "$ALERT_FILE")
    RISK_SCORE=$(jq -r '.risk_score' "$ALERT_FILE")
    RULE_ID=$(jq -r '.rule_id' "$ALERT_FILE")
    PROTOCOL=$(jq -r '.protocol' "$ALERT_FILE")
    
    log "Processing alert $ALERT_ID: $RULE_ID (Risk: $RISK_SCORE)"
}

# Add to blocklist
add_to_blocklist() {
    local ip="$1"
    local reason="$2"
    
    if [ "$ENABLE_ACTIONS" = true ]; then
        echo "$ip # $reason - $(date -u +"%Y-%m-%d %H:%M:%S")" >> "$BLOCKLIST_FILE"
        log "Added $ip to blocklist: $reason"
        
        # In a real scenario, would update Suricata/Snort rules
        # or firewall configuration here
    else
        log "DRY RUN: Would add $ip to blocklist: $reason"
    fi
}

# Create mock ticket
create_ticket() {
    local alert_id="$1"
    local source_ip="$2"
    local risk_score="$3"
    
    if [ "$ENABLE_ACTIONS" = true ]; then
        # Simulate API call to ticketing system
        curl -s -X POST "$MOCK_API_URL/ticket" \
            -H "Content-Type: application/json" \
            -d "{\"alert_id\":\"$alert_id\",\"source_ip\":\"$source_ip\",\"risk_score\":$risk_score}" \
            >> "$LOG_FILE" 2>&1
        
        log "Created mock ticket for alert $alert_id"
    else
        log "DRY RUN: Would create ticket for alert $alert_id"
    fi
}

# Quarantine host (simulated)
quarantine_host() {
    local ip="$1"
    
    if [ "$ENABLE_ACTIONS" = true ]; then
        # Simulate quarantine action
        # In real scenario, would call NAC or network enforcement API
        log "SIMULATED: Quarantined host $ip"
    else
        log "DRY RUN: Would quarantine host $ip"
    fi
}

# Main response logic
respond_to_alert() {
    parse_alert
    
    # Response based on risk score and rule type
    if [ "$RISK_SCORE" -ge 80 ]; then
        # High risk - immediate blocking
        add_to_blocklist "$DEST_IP" "High risk DLP alert: $RULE_ID"
        quarantine_host "$SOURCE_IP"
        create_ticket "$ALERT_ID" "$SOURCE_IP" "$RISK_SCORE"
        
    elif [ "$RISK_SCORE" -ge 60 ]; then
        # Medium risk - block destination and create ticket
        add_to_blocklist "$DEST_IP" "Medium risk DLP alert: $RULE_ID"
        create_ticket "$ALERT_ID" "$SOURCE_IP" "$RISK_SCORE"
        
    else
        # Low risk - create ticket only
        create_ticket "$ALERT_ID" "$SOURCE_IP" "$RISK_SCORE"
    fi
    
    # Protocol-specific responses
    case "$PROTOCOL" in
        "DNS")
            log "DNS-based exfil detected - consider blocking external DNS"
            ;;
        "HTTP")
            log "HTTP-based exfil detected - review proxy logs"
            ;;
        "FTP")
            log "FTP transfer detected - consider blocking FTP protocol"
            ;;
        "SMTP")
            log "Email exfil detected - review mail gateway logs"
            ;;
    esac
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--alert-file)
            ALERT_FILE="$2"
            shift 2
            ;;
        -e|--enable-actions)
            ENABLE_ACTIONS=true
            shift
            ;;
        -b|--blocklist)
            BLOCKLIST_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
if [ -z "$ALERT_FILE" ]; then
    echo "Error: Alert file required"
    usage
    exit 1
fi

log "Starting DLP auto-response processing"
confirm_actions
respond_to_alert
log "DLP auto-response completed"

exit 0
