# SIEM Dashboard for Logs - Ingest and Visualize Security Events

## What this tool is for:
A Security Information and Event Management (SIEM) system that collects, analyzes, and visualizes security events from multiple sources. Provides real-time monitoring, alerting, and correlation of security events across your infrastructure.

## Key Features:
1. **Log Ingestion** from multiple sources (syslog, files, APIs)
2. **Real-time Processing** and correlation
3. **Security Event Visualization** with dashboards
4. **Alerting** based on security rules
5. **Threat Intelligence** integration
6. **Compliance Reporting**

---

## Python Implementation (Elasticsearch + Kibana Alternative)

### Project Structure:
```
siem-dashboard/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── collectors.py
│   │   └── parsers.py
│   ├── analyze/
│   │   ├── __init__.py
│   │   ├── correlator.py
│   │   └── rules_engine.py
│   ├── visualize/
│   │   ├── __init__.py
│   │   ├── dashboard.py
│   │   └── charts.py
│   ├── database/
│   │   ├── __init__.py
│   │   └── models.py
│   └── config/
│       ├── __init__.py
│       └── settings.py
├── requirements.txt
├── docker-compose.yml
└── dash_app.py
```

## How to Run

### Development:
```bash
# Install dependencies
pip install -r requirements.txt

# Run the SIEM system
python app/main.py

# Access dashboard at http://localhost:8050
```

### Production with Docker:
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f siem-dashboard

# Access services:
# Dashboard: http://localhost:8050
# Kibana: http://localhost:5601
# Elasticsearch: http://localhost:9200
```

### Generate Sample Logs for Testing:
```bash
# Generate sample firewall logs
echo "$(date) firewall drop SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22" >> sample_firewall.log

# Generate sample web logs
echo '192.168.1.100 - - [$(date -u +"%d/%b/%Y:%H:%M:%S +0000")] "GET /admin HTTP/1.1" 404 512' >> sample_web.log

# Generate sample auth logs
echo "$(date) sshd[12345]: Failed password for root from 192.168.1.100 port 22" >> sample_auth.log
```

## Key Features:

1. **Multi-source Log Ingestion**: Syslog, file logs, JSON APIs
2. **Real-time Correlation**: Detect patterns across multiple events
3. **Security Rules Engine**: Customizable detection rules
4. **Interactive Dashboard**: Real-time visualization and monitoring
5. **Alerting System**: Automatic notification of security incidents
6. **Threat Intelligence**: Integration with external threat feeds
7. **Scalable Architecture**: Docker-based deployment

This SIEM implementation provides a comprehensive security monitoring solution that can be extended with additional log sources, correlation rules, and visualization components based on specific organizational needs.
