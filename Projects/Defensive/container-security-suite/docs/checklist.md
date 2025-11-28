# Container Security Hardening Checklist

## Build Phase
- [ ] Scan base images for vulnerabilities
- [ ] Use minimal base images (distroless, alpine)
- [ ] Run as non-root user
- [ ] Use multi-stage builds
- [ ] Scan for secrets in Dockerfile
- [ ] Generate SBOM for each build
- [ ] Sign images with cosign

## Registry Phase  
- [ ] Enable vulnerability scanning in registry
- [ ] Implement registry access controls
- [ ] Use immutable tags
- [ ] Scan images on push
- [ ] Quarantine vulnerable images

## Deploy Phase
- [ ] Validate image signatures
- [ ] Enforce security policies via admission control
- [ ] Require non-root users
- [ ] Drop all capabilities
- [ ] Set read-only root filesystem
- [ ] Apply seccomp/AppArmor profiles

## Runtime Phase
- [ ] Monitor runtime with Falco
- [ ] Limit resource usage
- [ ] Use network policies
- [ ] Regular security updates
- [ ] Runtime vulnerability scanning

## Emergency Playbook for Critical CVE

1. **Immediate Actions** (0-2 hours)
   - Identify affected containers
   - Quarantine vulnerable images
   - Notify security team

2. **Containment** (2-24 hours)  
   - Roll back deployments
   - Block vulnerable image pulls
   - Update firewall rules if needed

3. **Remediation** (24-72 hours)
   - Patch vulnerable packages
   - Build and test new images
   - Deploy updated containers

4. **Post-Incident** (>72 hours)
   - Root cause analysis
   - Update scanning rules
   - Review detection gaps
