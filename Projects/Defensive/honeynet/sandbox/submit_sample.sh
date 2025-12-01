#!/bin/bash
#
# Malware Sample Submission Script
# Safety: Requires explicit approval token for submission

set -e

CONFIRM_TOKEN=""
SAMPLE_PATH=""
CUCKOO_HOST="localhost:8090"
APPROVAL_REQUIRED=true

usage() {
    echo "Usage: $0 --sample <path> --approve-token <token>"
    echo "Safety: This script requires explicit approval for sample submission"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --sample)
            SAMPLE_PATH="$2"
            shift 2
            ;;
        --approve-token)
            CONFIRM_TOKEN="$2"
            shift 2
            ;;
        --no-approval)
            APPROVAL_REQUIRED=false
            shift
            ;;
        *)
            usage
            ;;
    esac
done

# Safety checks
if [[ "$APPROVAL_REQUIRED" == "true" && "$CONFIRM_TOKEN" != "HONEYNET_APPROVE_$(date +%Y%m%d)" ]]; then
    echo "ERROR: Valid approval token required for sample submission"
    exit 1
fi

if [[ ! -f "$SAMPLE_PATH" ]]; then
    echo "ERROR: Sample file not found: $SAMPLE_PATH"
    exit 1
fi

# Submit to Cuckoo sandbox
echo "Submitting sample to Cuckoo sandbox: $SAMPLE_PATH"
curl -X POST \
    -F "file=@$SAMPLE_PATH" \
    "http://$CUCKOO_HOST/tasks/create/file" \
    | python3 -m json.tool

echo "Sample submitted successfully"
