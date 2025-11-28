#!/bin/bash
#
# Test Kubernetes admission webhook

set -e

echo "Starting admission webhook integration test..."

# Create test namespace
kubectl create namespace security-test --dry-run=client -o yaml | kubectl apply -f -

# Deploy test webhook
kubectl apply -f k8s/admission-webhook/manifests/ -n container-security

# Wait for webhook to be ready
kubectl wait --for=condition=ready pod -l app=admission-webhook -n container-security --timeout=60s

echo "Testing unsigned image rejection..."
# This should be rejected
if kubectl run test-unsigned --image=untrusted.io/nginx:latest -n security-test 2>/dev/null; then
    echo "❌ TEST FAILED: Unsigned image was allowed"
    exit 1
else
    echo "✅ Unsigned image correctly rejected"
fi

echo "Testing approved image..."
# This should be allowed
if kubectl run test-approved --image=nginx:latest -n security-test; then
    echo "✅ Approved image correctly allowed"
    # Clean up
    kubectl delete pod test-approved -n security-test
else
    echo "❌ TEST FAILED: Approved image was rejected"
    exit 1
fi

echo "✅ All admission webhook tests passed"
