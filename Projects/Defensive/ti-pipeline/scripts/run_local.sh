#!/bin/bash

# Threat Intelligence Pipeline - Local Development Runner

set -e

echo "Starting Threat Intelligence Pipeline..."

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "Error: docker-compose is required but not installed."
    exit 1
fi

# Create sample IOCs directory
mkdir -p samples

# Create sample IOCs file if it doesn't exist
if [ ! -f samples/sample_iocs.csv ]; then
    cat > samples/sample_iocs.csv << EOF
indicator,type,confidence,description
malicious-domain.com,domain,80,Known malicious domain
1.2.3.4,ipv4,90,Suspicious C2 server
8.8.8.8,ipv4,10,Google DNS (benign test)
http://evil.com/path,url,85,Phishing URL
abcd1234abcd1234abcd1234abcd1234,md5,75,Malware sample
EOF
    echo "Created sample IOCs file: samples/sample_iocs.csv"
fi

# Copy environment template if .env doesn't exist
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Copied .env.example to .env"
        echo "Please review .env and configure any required settings"
    else
        echo "Warning: .env.example not found, creating basic .env"
        cat > .env << EOF
API_KEY=test-key-local-dev
MOCK_ENRICH=true
ENABLE_REAL_ENRICH=false
EOF
    fi
fi

echo "Starting services with docker-compose..."
docker-compose up --build -d

echo "Waiting for services to be healthy..."
sleep 30

# Check if API is responding
echo "Testing API connectivity..."
API_URL="http://localhost:8000"
API_KEY=$(grep API_KEY .env | cut -d '=' -f2)

if curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/stats" > /dev/null; then
    echo "API is responding correctly"
else
    echo "Warning: API is not responding as expected"
fi

# Ingest sample IOCs
echo "Ingesting sample IOCs..."
python scripts/ingest_feed.py samples/sample_iocs.csv --format csv --feed sample_feed

echo ""
echo "=== Threat Intelligence Pipeline is running ==="
echo "API: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo "MinIO Console: http://localhost:9001 (minioadmin/minioadmin)"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
echo ""
echo "Test search: curl -H 'Authorization: Bearer $API_KEY' '$API_URL/search?q=malicious'"
echo ""
