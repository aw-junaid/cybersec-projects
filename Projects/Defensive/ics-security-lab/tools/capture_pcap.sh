#!/bin/bash
# PCAP Capture Script for ICS Lab
# SAFETY: Only captures on lab networks

echo "=== ICS Lab PCAP Capture ==="
echo "SAFETY: This script only captures on lab networks"

# Verify lab mode
if [ "$LAB_MODE" != "1" ]; then
    echo "ERROR: Must run in lab mode with LAB_MODE=1"
    exit 1
fi

INTERFACE=${1:-eth0}
DURATION=${2:-300}
OUTPUT_FILE="ics_lab_capture_$(date +%Y%m%d_%H%M%S).pcap"

echo "Capturing on $INTERFACE for $DURATION seconds..."
echo "Output: $OUTPUT_FILE"

# Capture with filter for ICS protocols
timeout $DURATION tcpdump -i $INTERFACE -w $OUTPUT_FILE \
    port 502 or port 4840 or port 1883 or port 102

echo "Capture complete. File: $OUTPUT_FILE"
