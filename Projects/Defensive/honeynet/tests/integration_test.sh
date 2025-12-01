#!/bin/bash
#
# Honeynet Integration Tests
# Safety: Only runs in CI environment with HONEY_LAB_MODE=1

set -e

echo "Starting Honeynet integration tests..."

# Verify safety mode
if [[ "$HONEY_LAB_MODE" != "1" ]]; then
    echo "ERROR: HONEY_LAB_MODE not set to 1"
    exit 1
fi

# Start test stack
docker-compose -f docker-compose.test.yml up -d

# Wait for services
sleep 30

# Run tests
python3 tests/test_sensor_agent.py
python3 tests/test_ingest_service.py

# Cleanup
docker-compose -f docker-compose.test.yml down

echo "Integration tests completed successfully"
