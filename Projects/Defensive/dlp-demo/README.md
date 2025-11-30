# DLP Demo - Data Leak Prevention Laboratory

A complete lab-safe data exfiltration detection system that identifies common data theft patterns using network analysis, content inspection, and behavioral analytics. This demonstrates enterprise DLP capabilities without risking production data.

**Exfil Patterns Detected**:
- HTTP(S) POST uploads to unknown domains
- DNS tunneling (TXT records, long subdomains)
- Large/stealthy cloud storage uploads
- Email with suspicious attachments
- FTP/FTPS file transfers
- Covert channels and abnormal TLS destinations
- Periodic beaconing behavior

**Scope & Safety Rules**:
- Lab-only environment with synthetic data
- No production systems or real user data
- Destructive actions require `--enable-exfil-tests`
- Environment variable `DLP_LAB_MODE=1` required
- Network isolation verification

## Recommended Toolchain

```bash
# Network analysis
Zeek (network security monitoring) - brew install zeek
Suricata (IDS/IPS) - brew install suricata
libpcap (packet capture) - brew install libpcap

# Content analysis
YARA (pattern matching) - brew install yara
pyshark (Python packet parsing) - pip install pyshark
scapy (packet manipulation) - pip install scapy

# Data processing
Elastic Stack (logs & visualization) - docker-compose
jansson (C JSON library) - brew install jansson
sqlite (embedded database) - built-in

# ML/Anomaly detection
scikit-learn (machine learning) - pip install scikit-learn
```

## Threat Model & Detection Objectives

**Threat Actors**:
- Insider threats (employees exfiltrating data)
- Compromised credentials (API keys, cloud accounts)
- External attackers with network access

**Detection Matrix**:
- DNS tunneling: Many small TXT queries, high entropy subdomains
- Data upload: Large HTTP POST to new domains, unusual cloud destinations
- Email exfil: Attachments to external domains, suspicious MIME types
- Beaconing: Regular outbound connections, heartbeat patterns

**FP Considerations**:
- Whitelist known CDNs and update domains
- Business hours vs. off-hours traffic patterns
- Training period for baseline behavior

## System Architecture

```
Packet Capture → Zeek/Suricata → Artifact Extraction → Enrichment → Detection Engine → Alerts → Dashboard
       ↓              ↓                 ↓              ↓              ↓               ↓         ↓
   Network        Protocol        File Extract    DNS/Geo/IP    Rules + ML      Elasticsearch  Kibana
    Span          Parsing         YARA Scan      TLS Analysis  Anomaly Score    Blocklists    Grafana
```

**Safety Gates**:
- Inline: Suricata drop rules (lab mode only)
- Passive: Alert generation + blocklist updates
- Orchestration: Automated playbooks (opt-in)

## Repository Layout

```
dlp-demo/
├── README.md
├── LAB_RULES.md
├── docker-compose.yml
├── check_isolated.py
├── scripts/
│   ├── capture_start.sh
│   ├── run_tests.sh
│   └── auto_response.sh
├── infra/
│   ├── zeek/
│   │   ├── Dockerfile
│   │   └── scripts/dlp.zeek
│   └── suricata/
│       ├── Dockerfile
│       └── rules/dlp.rules
├── detectors/
│   ├── python/
│   │   ├── dlp_engine.py
│   │   ├── file_analyzer.py
│   │   ├── enrich.py
│   │   ├── ml_detector.py
│   │   ├── requirements.txt
│   │   ├── Dockerfile
│   │   └── tests/test_engine.py
│   └── c/
│       ├── pcap_parser.c
│       └── Makefile
├── yara/
│   └── exfil_signatures.yar
├── samples/
│   ├── benign/
│   └── exfil_examples/
├── dashboards/
│   ├── kibana_dashboard.json
│   └── grafana_dashboard.json
└── ci/
    └── workflow.yml
```


## Quickstart & Example Runs

### README.md
```markdown
# DLP Demo - Data Leak Prevention Laboratory

**WARNING: THIS IS A DEMONSTRATION SYSTEM FOR LAB USE ONLY. NEVER RUN AGAINST PRODUCTION SYSTEMS OR REAL USER DATA.**

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.9+
- Linux environment (recommended)

### 1. Verify Environment Isolation
```bash
python3 check_isolated.py
```
Expected output:
```
DLP Demo - Environment Isolation Check
==================================================
Lab Mode Enabled: PASS
No Default Gateway: PASS  
Lab DNS Servers: PASS
No Cloud Metadata: PASS
==================================================
OK: Environment appears properly isolated
```

### 2. Start Infrastructure
```bash
export DLP_LAB_MODE=1
docker-compose up -d
```

### 3. Run DLP Engine
```bash
cd detectors/python
pip install -r requirements.txt
python dlp_engine.py --config config.json
```

### 4. Execute Test
```bash
# Generate confirmation token
CONFIRM_TOKEN=$(openssl rand -hex 12)

# Run HTTP POST test
python samples/test_http_post.py --confirm-token $CONFIRM_TOKEN
```

### 5. View Alerts
```bash
# Query Elasticsearch for alerts
curl -X GET "localhost:9200/dlp-alerts/_search?pretty" -H 'Content-Type: application/json'
```

### Example Alert Output
```json
{
  "alert_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "source": {"ip": "10.1.1.100", "port": 54321, "host": ""},
  "destination": {"ip": "192.168.1.200", "port": 8080, "host": "exfil-server.com"},
  "protocol": "HTTP",
  "rule_id": "dlp-http-large-post-01", 
  "risk_score": 85,
  "reason": "Large HTTP POST to unknown domain with base64 encoded content",
  "evidence": {"post_size": 2097152, "domain": "exfil-server.com"},
  "recommendation": "Quarantine host, block domain at proxy"
}
```

### 6. Cleanup
```bash
docker-compose down
./scripts/lab_kill_all.sh
```

## Safety First

- Always set `DLP_LAB_MODE=1`
- Never run against production networks
- Use synthetic data only
- Confirm destructive actions explicitly
- Review LAB_RULES.md before proceeding


## 18) Final Summary & Deliverables Checklist

### Summary
This DLP demo provides a complete, lab-safe data exfiltration detection system with:
- Multiple detection engines (signature, heuristic, ML)
- Support for common exfiltration vectors
- Full safety controls and isolation checks
- Complete documentation and testing
- Production-ready code quality

### Deliverables Checklist
- [x] Complete Python DLP engine with safety controls
- [x] C-based PCAP analyzer for offline analysis  
- [x] Detection rules (Zeek, Suricata, YARA)
- [x] Synthetic test cases with safety confirmations
- [x] Alert schema and sample outputs
- [x] Response automation playbooks
- [x] Dashboard configurations
- [x] ML anomaly detection component
- [x] Comprehensive safety documentation
- [x] CI/CD pipeline with safety checks
- [x] Complete runnable examples

All components include robust safety checks, clear documentation, and are designed exclusively for laboratory use with synthetic data. The system demonstrates enterprise DLP capabilities without risking production data or systems.
