# Secure CI/CD Pipeline Reference Implementation

A secure CI/CD pipeline implementation that ensures artifact integrity through cryptographic signing, prevents vulnerabilities via automated scanning, enforces policies with code-based gates, and provides auditable supply-chain provenance. Protects against tampering, malicious dependencies, and unauthorized deployments.

## Threat model & security objectives

**Threats:**
- Tampered artifacts (malicious code injection)
- Malicious dependencies (typosquatting, compromised packages)
- Compromised build steps (CI runner compromise)
- Unscanned vulnerabilities reaching production
- Credential theft and misuse

**Objectives:**
- Cryptographic signing of all artifacts
- Comprehensive vulnerability scanning
- Supply-chain attestation capture
- Policy-based deployment gating
- Least privilege access control
- Reproducible builds

**Assumptions:**
- Access to container registry (GHCR/Docker Hub)
- CI systems with OIDC capability for keyless signing
- Out-of-scope: Network security, runtime protection, advanced secret management

## Recommended toolchain

- **cosign** - Artifact signing and verification with keyless options and transparency log integration
- **Trivy** - Comprehensive vulnerability scanning for containers, filesystems, and configs
- **in-toto** - Supply-chain attestation framework for verifying build steps
- **GitHub Actions** - CI/CD platform with native security features and OIDC
- **GitLab CI** - Alternative CI platform with integrated security scanning

## High-level architecture & data flows

```
Developer Push → Build → Test → Scan → Sign + Attest → Registry → Verify + Gate → Deploy
     ↓              ↓       ↓       ↓         ↓            ↓          ↓           ↓
   Git           Docker   Unit   Trivy     Cosign       GHCR      Policy     Kubernetes
   Repo          Build   Tests   Scan     in-toto       ECR       Check      Production
```

**Gating Points:**
1. CI Gates: Scan failures, test failures
2. CD Preflight: Signature verification, attestation validation
3. Admission Controller: Policy enforcement at deploy time

**Storage:**
- Artifacts: Container Registry (GHCR/ECR)
- Signatures: OCI registry alongside artifacts
- Attestations: OCI registry + Rekor transparency log


## Final summary + quickstart

**README.md**
# Secure CI/CD Pipeline Reference Implementation

A production-ready reference implementation demonstrating supply chain security best practices including artifact signing, vulnerability scanning, policy enforcement, and attestations.

## Quick Start

### Prerequisites
- Docker
- cosign, trivy, opa installed
- Container registry access

### Local Demo

1. **Build and scan the application:**
```bash
chmod +x scripts/*.sh
./scripts/build_and_scan.sh ghcr.io/your-org/test-app:latest
```

2. **Sign the image (keyless):**
```bash
./scripts/sign_with_cosign.sh ghcr.io/your-org/test-app:latest keyless
```

3. **Compile and run the C verifier:**
```bash
cd c-tools && make && cd ..
./c-tools/verifier ghcr.io/your-org/test-app:latest
```

4. **Run integration tests:**
```bash
./tests/integration_test.sh
```

### Expected Outputs

**Successful build:**
```
[INFO] Build and scan process completed successfully
{"status": "success", "image": "ghcr.io/org/app:latest", "scan_results": "./scan-results/trivy-scan.json"}
```

**Policy violation:**
```
[ERROR] Policy violation: 1 CRITICAL vulnerabilities found
Exit code: 1
```

**Verification passed:**
```
[INFO] All verification checks passed
Exit code: 0
```

## Pipeline Overview

1. **Build**: Multi-stage Docker build with security optimizations
2. **Scan**: Trivy vulnerability scanning with policy enforcement
3. **Sign**: Cryptographic signing using cosign (keyless or keyed)
4. **Attest**: Generate SBOM and vulnerability attestations
5. **Verify**: Signature and policy verification before deployment
6. **Deploy**: Gated deployment with comprehensive checks

## Security Features

- ✅ Cryptographic artifact signing
- ✅ Vulnerability scanning with policy gates
- ✅ Supply chain attestations
- ✅ Policy-as-code enforcement
- ✅ Keyless signing support
- ✅ Reproducible builds
- ✅ Comprehensive testing


## Extra guidance & trade-offs

**TRADE-OFFS.md**
# Security vs. Practicality Trade-offs

## Keyed vs Keyless Signing

**Keyed Signing:**
- ✅ Full control over keys
- ✅ Works in air-gapped environments
- ❌ Key management overhead
- ❌ Key rotation complexity

**Keyless Signing:**
- ✅ No key management
- ✅ Automatic transparency log integration
- ❌ Requires internet access
- ❌ Dependent on OIDC provider availability

## Scanning Depth vs Pipeline Speed

**Deep Scanning:**
- ✅ Comprehensive vulnerability detection
- ✅ Better security coverage
- ❌ Longer pipeline execution
- ❌ Higher resource usage

**Focused Scanning:**
- ✅ Faster pipeline execution
- ✅ Lower resource consumption
- ❌ May miss some vulnerabilities
- ❌ Reduced security coverage

## Recommendation
- Use keyless signing for cloud-native environments
- Implement cached vulnerability databases for speed
- Use severity-based policies to balance security and practicality
- Implement gradual rollout with canary deployments

## Scaling in Organizations

1. **Centralized Policy Management**
   - Shared policy libraries across teams
   - Centralized artifact registry with scanning
   - Unified signing authority

2. **Federated Execution**
   - Team-specific CI/CD pipelines
   - Shared security tooling
   - Centralized monitoring and audit

3. **Gradual Adoption**
   - Start with critical applications
   - Expand coverage gradually
   - Continuous education and training
