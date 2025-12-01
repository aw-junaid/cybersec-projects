**HoneyLab** is a secure, distributed honeynet platform that deploys diverse deception sensors across networks to collect attacker TTPs, malware, and threat intelligence. It provides centralized logging, analysis, and alerting while enforcing strict safety controls to prevent misuse and lateral movement.

**Use Cases**: Malware collection, attacker profiling, threat intelligence, TTP research, deception & early warning.

**SAFETY NOTICE**: This platform is designed for isolated lab environments only. Do not connect to production systems. Obtain legal approvals before deployment. All network-interacting components require explicit safety confirmation.

## Threat Model & Permitted Scope

**Attacker Goals Emulated/Observed**:
- Credential theft (SSH/Telnet brute force)
- C2 beaconing and callback establishment
- Network scanning and reconnaissance
- Service exploitation (web, SMB, industrial protocols)
- Lateral movement attempts
- Malware deployment and exfiltration

**Permitted Researcher Actions**:
- Passive collection of attacker interactions
- Analysis of captured artifacts in sandbox
- Development of detection rules from observed TTPs
- Safe interaction within contained honeypot environments

**Prohibited Actions**:
- Active exploitation against real external targets
- Using captured infrastructure to pivot to other networks
- Storing PII without proper handling procedures
- Sharing collected data without anonymization

**Containment Policies**:
- No outbound network access from honeypot containers
- All artifacts quarantined and analyzed before processing
- Strict egress filtering on sensor networks
- Automatic revocation of compromised nodes

## High-Level Architecture & Dataflow

```
[Distributed Sensors] → [Local Agent] → [TLS+Auth] → [Message Broker] → [Ingest Pipeline]
       ↓                                       ↓
[PCAP/Logs]                            [Central Storage]
       ↓                                       ↓
[Artifact Extraction]                  [Analysis & Enrichment]
                                              ↓
                                    [Alerting & Dashboards]
                                              ↓
                                    [Sandbox & Quarantine]
```

**Data Flow**:
1. Sensors (Cowrie, Glastopf, etc.) generate logs and PCAPs
2. Local agent collects, enriches, and signs data
3. Encrypted transport to central Kafka/RabbitMQ
4. Logstash/Fluentd processes and enriches events
5. Storage in Elasticsearch/ClickHouse + MinIO for artifacts
6. Analysis (YARA, Zeek, Suricata) triggers alerts
7. Dashboards (Kibana/Grafana) visualize threats
8. Suspicious samples sent to Cuckoo sandbox

**Security Controls**:
- Mutual TLS for all communications
- Signed registration tokens for node authentication
- Strict egress firewall rules on sensors
- Artifact quarantine with encryption
- Rate limiting and backpressure handling

## Deployment Modes & Topology Examples

**Small Lab**:
```
[Internet] → [Firewall] → [Sensor VLAN] → [Central Server]
                    (Docker containers on single host)
```

**Multi-Site**:
```
Site A: [Sensors] → [Local Collector] → [VPN] → [Central]
Site B: [Sensors] → [Local Collector] → [VPN] → [Central]
```

**Cloud Hybrid**:
```
[K8s Cluster] → [DaemonSet Sensors] → [Sidecar Agent] → [Cloud Broker]
```

## Recommended Toolchain

- **Zeek**: Network security monitoring (`apt install zeek`)
- **Suricata**: IDS/IPS with file extraction (`apt install suricata`)
- **Cowrie**: SSH/Telnet honeypot (`docker pull cowrie/cowrie`)
- **Conpot**: Industrial control system honeypot (`pip install conpot`)
- **Glastopf**: Web application honeypot (`docker pull glastopf/glastopf`)
- **Kafka**: Distributed message bus (`docker-compose up kafka`)
- **Fluentd**: Log forwarder (`docker pull fluent/fluentd`)
- **Elasticsearch**: Search and analytics (`docker pull elasticsearch`)
- **MinIO**: S3-compatible object storage (`docker pull minio/minio`)
- **Cuckoo Sandbox**: Automated malware analysis (`docker pull cuckoo/sandbox`)
- **YARA**: Pattern matching tool (`apt install yara`)
- **Grafana**: Dashboard platform (`docker pull grafana/grafana`)

## Repo & File Layout

```
honeynet/
  README.md
  docker-compose.yml
  infra/
    k8s/
    certs/
  sensors/
    ssh_cowrie/
    http_glastopf/
    modbus_conpot/
    custom_python/
  collector/
    agent/
    broker/
    logstash/
    ingest_service/
  analysis/
    zeek_scripts/
    suricata_rules/
    yara/
    ml/
  sandbox/
    cuckoo/
  dashboards/
    kibana/
    grafana/
  tools/
    c/
    python/
  tests/
  scripts/
    deploy.sh
    start_lab.sh
    check_isolated.py
    kill_all.sh
  ci/
    workflow.yml
  docs/
    LAB_RULES.md
    OPERATION.md
```

## Privacy, Safety & Legal Controls

# Honeynet Lab Rules & Safety Procedures

## Legal & Ethical Guidelines

### Required Approvals
- Written approval from legal counsel required before deployment
- Notification to relevant authorities if required by local laws
- Consent for data collection and retention periods

### Prohibited Activities
- Never deploy honeypots on production networks
- Never use collected data for malicious purposes
- Never attempt to counter-attack or hack back
- Never store PII without proper handling procedures

### Data Handling
- Anonymize all IP addresses before sharing
- Encrypt all stored data at rest
- Implement strict access controls
- Define and enforce data retention policies

## Safety Procedures

### Network Isolation
- All sensors must be on isolated VLANs
- No outbound internet access from honeypots
- Regular network isolation checks required

### Incident Response
- Immediate revocation of compromised nodes
- Preservation of evidence for legal purposes
- Notification procedures for data breaches

## Operational Controls

### Access Control
- Two-person rule for sensitive operations
- Role-based access control enforced
- All actions logged and audited

### Change Management
- All changes require peer review
- Emergency change procedures documented
- Regular security reviews required


## Hardening & Operational Guidance

**Security Hardening Checklist**:
- Run all containers as non-root users
- Use read-only root filesystems where possible
- Drop all Linux capabilities
- Apply seccomp profiles
- Use no-new-privileges flag
- Implement resource limits
- Regular vulnerability scanning
- Certificate rotation every 90 days

## Documentation & Runbook

# Honeynet Platform


## Quick Start

1. **Verify Isolation**
   ```bash
   export HONEY_LAB_MODE=1
   python3 scripts/check_isolated.py
   ```

2. **Generate Certificates**
   ```bash
   scripts/generate_certs.sh
   ```

3. **Start Platform**
   ```bash
   docker-compose up -d
   ```

4. **Enroll Sensor**
   ```bash
   scripts/enroll_sensor.sh --token $(cat infra/certs/node-token.txt)
   ```

5. **Test with Safe Probe**
   ```bash
   scripts/tests/simulate_ssh_bruteforce.sh --confirm-token TEST_APPROVAL_$(date +%Y%m%d)
   ```

## Access Dashboards

- Kibana: http://localhost:5601
- Grafana: http://localhost:3000
- MinIO: http://localhost:9001

## Emergency Shutdown

```bash
scripts/kill_all.sh
```

## Full Documentation

See `docs/OPERATION.md` for detailed operational procedures.



## Final Summary & Next Steps

This implementation provides a complete, safe honeynet platform with:

**Key Features**:
- Distributed sensor architecture with safety controls
- Centralized logging and analysis pipeline
- Malware analysis and artifact handling
- Comprehensive detection rules
- Operational safety procedures

**Safety First Approach**:
- Network isolation requirements
- Explicit safety confirmations
- No outbound access from honeypots
- Legal and ethical guidelines

**Next Steps for Deployment**:
1. Review and customize `docs/LAB_RULES.md` for your organization
2. Obtain legal approvals for deployment
3. Set up isolated lab network environment
4. Generate proper TLS certificates and tokens
5. Deploy in staging for testing
6. Gradually roll out sensors
7. Establish operational procedures

**Scaling Recommendations**:
- Shard Elasticsearch indices by date
- Partition Kafka topics by sensor type
- Use Kubernetes for sensor fleet management
- Implement hierarchical storage management

This platform provides a solid foundation for safe, effective threat intelligence gathering while maintaining strict security and legal compliance.
