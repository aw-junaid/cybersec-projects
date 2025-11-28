#!/bin/bash
# Emergency Kill Switch for ICS Lab
# Stops all lab containers and networks

echo "=== ICS Lab Emergency Shutdown ==="
echo "WARNING: This will stop ALL lab containers"

read -p "Type 'SHUTDOWN_ICS_LAB' to confirm: " confirmation
if [ "$confirmation" != "SHUTDOWN_ICS_LAB" ]; then
    echo "Shutdown cancelled"
    exit 1
fi

echo "Stopping containers..."
docker-compose -f lab/docker-compose.yml down

echo "Removing lab networks..."
docker network rm ics-lab 2>/dev/null || true

echo "Cleaning up..."
docker system prune -f

echo "✅ Lab shutdown complete"
echo "REMINDER: Verify all lab components are stopped before leaving"
