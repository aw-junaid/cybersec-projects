package policy

import future.keywords.in

# Default deny
default allow = false

# Allow if all conditions are met
allow {
    # Image must be signed
    image_is_signed
    
    # No critical vulnerabilities
    not has_critical_vulnerabilities
    
    # High vulnerabilities below threshold
    high_vulnerabilities_below_threshold
    
    # Has valid attestations
    has_valid_attestations
    
    # Built from trusted source
    built_from_trusted_source
}

# Check if image is signed
image_is_signed {
    # This would typically check cosign verification results
    # For demo, we assume this is passed as input
    input.signature_verified == true
}

# Check for critical vulnerabilities
has_critical_vulnerabilities {
    some i, j
    vuln := input.Results[i].Vulnerabilities[j]
    vuln.Severity == "CRITICAL"
}

# Allow up to 5 high severity vulnerabilities
high_vulnerabilities_below_threshold {
    count(high_vulnerabilities) <= 5
}

high_vulnerabilities[vuln] {
    some i, j
    vuln := input.Results[i].Vulnerabilities[j]
    vuln.Severity == "HIGH"
}

# Check for valid attestations
has_valid_attestations {
    # This would verify in-toto attestations
    # For demo, we check that basic attestation data exists
    input.attestations.build_provenance != null
    input.attestations.vulnerability_scan != null
}

# Verify build source
built_from_trusted_source {
    input.build_info.source == "github.com"
    input.build_info.branch == "main"
}

# Detailed denial messages
deny[msg] {
    not image_is_signed
    msg := "Image signature verification failed"
}

deny[msg] {
    has_critical_vulnerabilities
    msg := "Critical vulnerabilities found in image"
}

deny[msg] {
    count(high_vulnerabilities) > 5
    msg := sprintf("Too many high severity vulnerabilities: %d found", [count(high_vulnerabilities)])
}

deny[msg] {
    not has_valid_attestations
    msg := "Missing or invalid attestations"
}
