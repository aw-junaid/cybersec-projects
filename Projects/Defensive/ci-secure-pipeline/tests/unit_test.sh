#!/bin/bash
set -euo pipefail

# Test configuration
TEST_IMAGE="localhost:5000/test-app:latest"
SCAN_DIR="./test-scan-results"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

setup() {
    echo "Setting up test environment..."
    mkdir -p "$SCAN_DIR"
    # Build test image
    docker build -t "$TEST_IMAGE" -f src/Dockerfile . > /dev/null 2>&1
}

cleanup() {
    echo "Cleaning up..."
    docker rmi "$TEST_IMAGE" 2>/dev/null || true
    rm -rf "$SCAN_DIR"
}

test_build_script() {
    echo "Testing build_and_scan.sh..."
    if ./scripts/build_and_scan.sh "$TEST_IMAGE" "$SCAN_DIR"; then
        echo -e "${GREEN}✓ Build script test passed${NC}"
        return 0
    else
        echo -e "${RED}✗ Build script test failed${NC}"
        return 1
    fi
}

test_verifier_compilation() {
    echo "Testing C verifier compilation..."
    pushd c-tools > /dev/null
    if make; then
        echo -e "${GREEN}✓ C verifier compilation test passed${NC}"
        popd > /dev/null
        return 0
    else
        echo -e "${RED}✗ C verifier compilation test failed${NC}"
        popd > /dev/null
        return 1
    fi
}

test_policy_evaluation() {
    echo "Testing OPA policy evaluation..."
    
    # Create test scan results with critical vulnerability
    cat > "$SCAN_DIR/test-scan.json" << EOF
{
    "Results": [
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-1234",
                    "Severity": "CRITICAL",
                    "Title": "Test Critical Vulnerability"
                }
            ]
        }
    ]
}
EOF
    
    if opa eval --format pretty --data policy/gate.rego \
        --input "$SCAN_DIR/test-scan.json" "data.policy.allow" | grep -q "false"; then
        echo -e "${GREEN}✓ Policy evaluation test passed${NC}"
        return 0
    else
        echo -e "${RED}✗ Policy evaluation test failed${NC}"
        return 1
    fi
}

run_all_tests() {
    local failed=0
    
    setup
    
    test_build_script || failed=1
    test_verifier_compilation || failed=1
    test_policy_evaluation || failed=1
    
    cleanup
    
    if [ $failed -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed!${NC}"
    else
        echo -e "\n${RED}Some tests failed${NC}"
    fi
    
    return $failed
}

# Main execution
if [ "${1:-}" = "ci" ]; then
    run_all_tests
else
    echo "Running tests in interactive mode..."
    run_all_tests
fi
