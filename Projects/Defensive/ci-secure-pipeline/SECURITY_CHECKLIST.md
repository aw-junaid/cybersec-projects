# CI/CD Security Hardening Checklist

## ✅ Identity & Access Management
- [ ] Use OIDC for cloud provider authentication
- [ ] Implement least privilege for CI runners
- [ ] Use short-lived tokens instead of long-lived credentials
- [ ] Regular access reviews for CI/CD systems

## ✅ Code Security
- [ ] Require signed commits
- [ ] Protect main branch (require PR, reviews)
- [ ] Automated dependency updates
- [ ] SAST scanning in CI

## ✅ Build Security
- [ ] Use minimal base images
- [ ] Multi-stage builds to reduce attack surface
- [ ] Non-root container users
- [ ] Regular base image updates

## ✅ Artifact Security
- [ ] Sign all artifacts cryptographically
- [ ] Store signatures in tamper-proof log (Rekor)
- [ ] Generate SBOM for all artifacts
- [ ] Verify attestations before deployment

## ✅ Deployment Security
- [ ] Policy-based deployment gates
- [ ] Signature verification in CD
- [ ] Vulnerability scanning in registry
- [ ] Runtime security monitoring

## ✅ Monitoring & Audit
- [ ] Comprehensive CI/CD logging
- [ ] Alert on policy violations
- [ ] Regular audit of CI/CD access
- [ ] Incident response plan

## Quick Commands for Verification:

# Check image signatures
cosign verify ghcr.io/org/image:tag

# Verify attestations
cosign verify-attestation --type vuln ghcr.io/org/image:tag

# Check running processes as non-root
docker run --user 1001 image-name ps aux

# Test privilege escalation
docker run --security-opt=no-new-privileges image-name
