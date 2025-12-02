**Threat Intelligence Pipeline**: A scalable platform that automatically collects, enriches, scores, and deduplicates security indicators. Provides SOC analysts and CTI teams with enriched IOCs, provenance tracking, and actionable intelligence through APIs and dashboards.

---

## 1) Threat Model & Scope

**In-Scope IOC Types**:
- Malicious IPs, domains, URLs, and file hashes
- C2 communication patterns and beaconing
- YARA rule matches from endpoint/network scans
- Phishing artifacts (suspicious domains, URLs, attachments)
- SSL/TLS certificate anomalies
- Passive DNS anomalies and fast-flux domains

**Out-of-Scope**:
- Active offensive operations or countermeasures
- Direct interaction with live malicious infrastructure
- Automated takedown requests
- PII scanning beyond security context

**Ethics & Legal**: All operations require proper authorization. No PII sent to third parties without explicit consent. Follow GDPR, CCPA, and organizational privacy policies.

---

Now I'll create the complete repository structure with all files:


# Threat Intelligence Pipeline

A production-grade platform for collecting, enriching, scoring, and analyzing security indicators.

## Features

- **Multi-source Ingestion**: STIX/TAXII, CSV, JSON, MISP, syslog
- **Intelligent Enrichment**: VirusTotal, Passive DNS, WHOIS, Shodan, URLScan
- **Scoring & Deduplication**: Configurable scoring engine with canonicalization
- **Provenance Tracking**: Full audit trail for all indicators
- **REST API & Dashboard**: Search, timeline views, analyst workflows
- **SOAR Integration**: Alerting and playbook automation

## Quick Start

```bash
# Copy environment template
cp .env.example .env

# Start services
docker-compose up --build

# Ingest sample IOCs
python scripts/ingest_feed.py samples/sample_iocs.csv

# Query API
curl -H "Authorization: Bearer test-key" http://localhost:8000/search?q=malicious.com
```

## Security Notes

- Defaults to MOCK mode for all enrichment providers
- No external API calls without explicit consent
- All secrets via environment variables
- Rate limiting and circuit breaking enabled

See [docs/RUNNING.md](docs/RUNNING.md) for detailed instructions.
```


# Running the Threat Intelligence Pipeline

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.8+ (for local development)
- 4GB RAM minimum, 8GB recommended

### 1. Clone and Setup
```bash
git clone <repository>
cd ti-pipeline
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Review and edit .env if needed
# Important: By default, MOCK_ENRICH=true for safety
```

### 3. Start Services
```bash
# Start all services
./scripts/run_local.sh

# Or manually with docker-compose
docker-compose up --build -d
```

### 4. Verify Installation
```bash
# Check service status
docker-compose ps

# Test API connectivity
curl -H "Authorization: Bearer test-key" http://localhost:8000/stats
```

### 5. Ingest Sample Data
```bash
# Ingest sample IOCs
python scripts/ingest_feed.py samples/sample_iocs.csv --format csv --feed sample_feed

# Or create your own CSV/JSON file and ingest it
```

### 6. Access Interfaces
- **API & Documentation**: http://localhost:8000/docs
- **MinIO Console**: http://localhost:9001 (minioadmin/minioadmin)
- **Dashboard**: Open `ui/dashboard/index.html` in browser

## Using the API

### Authentication
All API requests require an API key in the Authorization header:
```bash
curl -H "Authorization: Bearer your-api-key" http://localhost:8000/endpoint
```

### Key Endpoints

#### Ingest IOCs
```bash
curl -X POST http://localhost:8000/ingest \
  -H "Authorization: Bearer test-key" \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      {
        "value": "malicious-domain.com",
        "type": "domain",
        "source": "my_feed",
        "confidence": 85,
        "description": "Known malicious domain"
      }
    ],
    "feed_name": "custom_feed"
  }'
```

#### Search IOCs
```bash
curl -H "Authorization: Bearer test-key" \
  "http://localhost:8000/search?q=malicious&type=domain"
```

#### Get IOC Details
```bash
curl -H "Authorization: Bearer test-key" \
  "http://localhost:8000/ioc/{ioc_id}"
```

#### Export STIX
```bash
curl -H "Authorization: Bearer test-key" \
  "http://localhost:8000/exports/stix?since=2024-01-01T00:00:00Z"
```

## Enabling Real Enrichment

### Safety First
By default, the system runs in MOCK mode to prevent accidental API calls. To enable real enrichment:

### Obtain API Keys
Get API keys from providers:
- VirusTotal: https://www.virustotal.com/gui/join-us
- Shodan: https://account.shodan.io/
- URLScan: https://urlscan.io/about-api/
- WHOIS XML API: https://whois.whoisxmlapi.com/

### Update Environment
Edit `.env` file:
```bash
# Enable real enrichment
MOCK_ENRICH=false
ENABLE_REAL_ENRICH=true

# Add your API keys
VT_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
URLSCAN_API_KEY=your_urlscan_key
WHOISXML_API_KEY=your_whois_key
```

### 3. Restart Services
```bash
docker-compose down
docker-compose up -d
```

### 4. Verify Configuration
```bash
# Check that mock mode is disabled
curl -H "Authorization: Bearer test-key" http://localhost:8000/stats | grep mock
```

## Using C Tools

### Build Tools
```bash
cd c_tools
make all
```

### Parse PCAP Files
```bash
./pcap_parser capture.pcap > iocs.json
```

### Parse Certificates
```bash
./cert_parser certificate.pem > cert_info.json
```

## Development

### Running Tests
```bash
# Unit tests
pytest tests/ -v

# End-to-end tests (requires services running)
pytest tests/test_end_to_end.py -v

# With coverage
pytest --cov=api --cov=workers tests/
```

### Adding New Enrichment Providers

1. Create provider module in `workers/tasks/`:
```python
# workers/tasks/new_provider.py
async def enrich(value: str, ioc_type: str) -> Dict:
    if MOCK_ENRICH:
        return await mock_enrich(value, ioc_type)
    return await real_enrich(value, ioc_type)
```

2. Add to enrichment mapping in `workers/enrich_worker.py`:
```python
module_map = {
    # ... existing providers
    'new_provider': 'workers.tasks.new_provider',
}
```

3. Update rate limits in `workers/enrich_worker.py`:
```python
RATE_LIMITS = {
    # ... existing limits
    'new_provider': (10, 60),  # 10 requests per minute
}
```

## Monitoring & Metrics

### Prometheus Metrics
Access metrics at: `http://localhost:8000/metrics`

Key metrics:
- `ingestion_requests_total`
- `enrichment_requests_total`
- `enrichment_duration_seconds`
- `cache_hits_total`

### Logs
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f api
docker-compose logs -f worker
```

## Troubleshooting

### Common Issues

**Services not starting:**
- Check Docker daemon is running
- Verify ports 8000, 5432, 6379, 9000-9001 are available

**API connection refused:**
- Wait for services to fully start (30+ seconds)
- Check `docker-compose ps` for healthy status

**Enrichment not working:**
- Verify `MOCK_ENRICH=false` and `ENABLE_REAL_ENRICH=true`
- Check API keys are set correctly
- Review worker logs for errors

**Database errors:**
- Run `docker-compose down -v` to reset volumes
- Check init scripts in `infra/init_db.sql`

### Getting Help
- Check service logs: `docker-compose logs [service]`
- Verify environment variables match `.env` file
- Ensure sufficient disk space and memory
- Review provider API documentation for rate limits

## Production Deployment

For production deployment, see the Kubernetes manifests in `infra/k8s/` and ensure:

1. Proper secret management (Kubernetes Secrets, HashiCorp Vault)
2. Database backups and monitoring
3. Rate limiting and API quotas
4. Security hardening and network policies
5. Regular dependency updates

# Legal & Privacy Guidelines

## Overview

This Threat Intelligence Pipeline handles potentially sensitive security data. All users must comply with applicable laws, regulations, and organizational policies.

## Data Handling

### Personal Identifiable Information (PII)

**Strict Prohibitions:**
- Do not ingest PII such as names, email addresses, phone numbers, or personal documents
- Do not use the system to scan internal user data without explicit authorization
- Implement data minimization - only collect what is necessary for security purposes

**If PII is accidentally ingested:**
1. Immediately delete the affected IOCs via API or database
2. Purge related enrichment records
3. Document the incident per organizational policy

### Third-Party Data Sharing

**Enrichment Providers:**
When using real enrichment mode, data is shared with third-party providers. Understand what each provider collects:

- **VirusTotal**: Shared samples and indicators may become publicly visible
- **Shodan**: IP scan requests are logged and may influence reputation scores
- **URLScan**: Scanned URLs and content may be stored and analyzed
- **WHOIS**: Domain lookup data is typically not sensitive but check provider TOS

**Best Practices:**
- Review each provider's Terms of Service and Privacy Policy
- Use mock mode when testing or developing
- Consider data sensitivity before enabling real enrichment
- Implement data classification and handling procedures

## Legal Compliance

### Jurisdictional Considerations

**GDPR (EU):**
- Implement data protection by design and default
- Maintain records of processing activities
- Honor right to erasure requests for accidental PII ingestion

**CCPA (California):**
- Provide opt-out mechanisms for data sharing
- Maintain records of data sales/sharing

**Sector-Specific Regulations:**
- **Healthcare**: HIPAA compliance for any protected health information
- **Finance**: GLBA requirements for financial data
- **Government**: FISMA, FedRAMP, or other applicable frameworks

### Lawful Use

**Authorized Purposes Only:**
- Use only for defensive security operations
- Ensure proper authorization for all monitored infrastructure
- Do not use for offensive operations or unauthorized access

**Intellectual Property:**
- Respect copyright and intellectual property rights
- Do not ingest proprietary data without permission
- Follow responsible disclosure practices

## Operational Security

### Access Controls

**Minimum Privilege:**
- Restrict API key access to authorized personnel
- Implement role-based access control for different user types
- Regularly review and audit access logs

**Secure Configuration:**
- Change default passwords and API keys
- Use secure communication (HTTPS/TLS)
- Implement network segmentation where possible

### Incident Response

**Data Breach Procedures:**
- Have a plan for potential data exposure
- Know regulatory reporting requirements
- Maintain contact information for legal counsel

**Forensic Readiness:**
- Preserve audit logs for investigative purposes
- Maintain chain of custody procedures
- Document all security incidents

## Provider-Specific Guidelines

### VirusTotal
- API usage subject to [VirusTotal Terms of Service](https://www.virustotal.com/gui/terms-of-service)
- Free tier: 4 requests/minute, 500 requests/day
- Data submitted may be shared with partners and the security community

### Shodan
- Governed by [Shodan Terms of Service](https://legal.shodan.io/)
- Respect scanned systems' acceptable use policies
- Do not use for unauthorized scanning

### URLScan
- Follow [URLScan Acceptable Use Policy](https://urlscan.io/about/)
- Scans may be publicly visible depending on visibility settings
- Respect robots.txt and rate limits

### WHOIS XML API
- Check [WHOIS XML API Terms](https://whois.whoisxmlapi.com/terms)
- Bulk queries may require commercial licensing
- Respect domain privacy preferences

## Risk Mitigation

### Technical Controls
- Default to mock mode for safety
- Implement comprehensive logging and monitoring
- Use rate limiting to prevent accidental overuse
- Regular security assessments and penetration testing

### Administrative Controls
- Security awareness training for all users
- Regular legal and compliance reviews
- Incident response planning and testing
- Vendor risk management for enrichment providers

### Organizational Policies
- Clear acceptable use policy for the platform
- Data classification and handling procedures
- Regular audit and compliance reporting
- Executive oversight and accountability

## Disclaimer

This document provides general guidance but does not constitute legal advice. Consult with legal counsel to ensure compliance with all applicable laws and regulations specific to your organization and jurisdiction.

The developers of this pipeline are not liable for misuse or violations of laws, regulations, or third-party terms of service. Users are responsible for proper implementation and operation.


## Final Summary & Next Steps

### What Was Generated

A complete, production-grade Threat Intelligence pipeline with:

**Core Components:**
- **FastAPI REST API** with authentication, rate limiting, and OpenAPI docs
- **Async enrichment workers** with provider plugins (VirusTotal, Shodan, WHOIS, etc.)
- **PostgreSQL storage** with full provenance tracking
- **Redis caching** with TTL policies
- **MinIO object storage** for artifacts
- **C utilities** for PCAP parsing and certificate analysis
- **Web dashboard** for SOC analyst interface
- **Comprehensive testing** and CI/CD pipeline

**Safety Features:**
- **Mock-first design** - no external API calls by default
- **Environment variable configuration** - no hardcoded secrets
- **Rate limiting and circuit breaking**
- **Comprehensive error handling**
- **Audit logging** for all enrichment calls

**Operational Excellence:**
- **Docker Compose** for local development
- **Prometheus metrics** and health checks
- **Structured logging**
- **Database migrations** and retention policies
- **Legal and privacy documentation**

### Recommended Next Steps

1. **Deploy to Staging Environment**
   ```bash
   # Test with sample data
   ./scripts/run_local.sh
   # Verify all components work together
   ```

2. **Configure Provider Keys**
   - Obtain API keys from VirusTotal, Shodan, etc.
   - Update `.env` with real credentials
   - Enable real enrichment cautiously

3. **Tune Scoring Weights**
   - Adjust confidence calculations based on your organization's risk profile
   - Customize enrichment provider priorities

4. **Run Historical Enrichment**
   - Ingest existing IOC feeds
   - Process historical PCAP files with C tools
   - Build baseline of enriched indicators

5. **Operationalize**
   - Set up monitoring and alerting
   - Configure backup and retention policies
   - Train SOC analysts on the dashboard
   - Integrate with existing SOAR/SIEM systems

6. **Scale for Production**
   - Deploy to Kubernetes using manifests in `infra/k8s/`
   - Implement proper secret management
   - Set up database clustering and replication
   - Configure load balancing and auto-scaling

The pipeline is now ready for development and testing. The mock-first approach ensures safe experimentation, while the production-ready architecture supports scaling to enterprise workloads.
