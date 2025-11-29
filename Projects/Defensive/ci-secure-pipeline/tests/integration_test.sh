#!/bin/bash
set -euo pipefail

# Integration test for the secure pipeline
echo "Running integration tests for secure CI/CD pipeline..."

# Test variables
TEST_IMAGE="localhost:5000/integration-test:latest"
TEST_SCAN_DIR="./integration-scan-results"

# Setup
mkdir -p "$TEST_SCAN_DIR"

# Test 1: Build and scan with critical vulnerability simulation
echo "1. Testing build and scan with policy violation..."
cat > "$TEST_SCAN_DIR/mock-scan.json" << EOF
{
    "Results": [
        {
            "Target": "test-image",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-12345",
                    "Severity": "CRITICAL",
                    "Title": "Integration Test Critical Vuln"
                },
                {
                    "VulnerabilityID": "CVE-2023-54321", 
                    "Severity": "HIGH",
                    "Title": "Integration Test High Vuln"
                }
            ]
        }
    ]
}
EOF

# Test policy evaluation
if opa eval --format pretty --data policy/gate.rego \
    --input "$TEST_SCAN_DIR/mock-scan.json" "data.policy.allow" 2>/dev/null | grep -q "false"; then
    echo "✓ Correctly blocked image with critical vulnerabilities"
else
    echo "✗ Failed to block image with critical vulnerabilities"
    exit 1
fi

# Test 2: Build and scan with no critical vulnerabilities
echo "2. Testing build and scan with compliant image..."
cat > "$TEST_SCAN_DIR/mock-scan-clean.json" << EOF
{
    "Results": [
        {
            "Target": "test-image",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-11111",
                    "Severity": "MEDIUM", 
                    "Title": "Integration Test Medium Vuln"
                }
            ]
        }
    ],
    "signature_verified": true,
    "attestations": {
        "build_provenance": {"builder": "github-actions"},
        "vulnerability_scan": {"scanner": "trivy"}
    },
    "build_info": {
        "source": "github.com",
        "branch": "main"
    }
}
EOF

if opa eval --format pretty --data policy/gate.rego \
    --input "$TEST_SCAN_DIR/mock-scan-clean.json" "data.policy.allow" 2>/dev/null | grep -q "true"; then
    echo "✓ Correctly allowed compliant image"
else
    echo "✗ Failed to allow compliant image"
    exit 1
fi

# Test 3: C verifier functionality
echo "3. Testing C verifier compilation and basic functionality..."
pushd c-tools > /dev/null
if make clean && make; then
    echo "✓ C verifier compiled successfully"
    # Test basic help/error output
    if ./verifier 2>&1 | grep -q "Usage"; then
        echo "✓ C verifier shows usage on error"
    else
        echo "✗ C verifier usage output incorrect"
        exit 1
    fi
else
    echo "✗ C verifier compilation failed"
    exit 1
fi
popd > /dev/null

# Cleanup
rm -rf "$TEST_SCAN_DIR"

echo ""
echo "✅ All integration tests passed!"
