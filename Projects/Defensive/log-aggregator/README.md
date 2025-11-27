# Log Aggregation & Parser Tools - Normalize and Search Logs

## What this tool is for:
A comprehensive log aggregation system that collects, parses, normalizes, and indexes logs from multiple sources. Provides powerful search capabilities, real-time processing, and unified log management.

## Key Features:
1. **Multi-source log collection** (files, syslog, HTTP, databases)
2. **Real-time log parsing and normalization**
3. **Flexible log routing and filtering**
4. **Powerful search and query language**
5. **Log enrichment and correlation**
6. **Alerting and monitoring**

---

## Python Implementation

### Project Structure:
```
log-aggregator/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── file_collector.py
│   │   ├── syslog_collector.py
│   │   └── http_collector.py
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base_parser.py
│   │   ├── apache_parser.py
│   │   ├── nginx_parser.py
│   │   ├── json_parser.py
│   │   └── syslog_parser.py
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── normalizer.py
│   │   ├── enricher.py
│   │   └── router.py
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── elasticsearch_store.py
│   │   ├── database_store.py
│   │   └── file_store.py
│   ├── search/
│   │   ├── __init__.py
│   │   ├── query_engine.py
│   │   └── indexer.py
│   └── api/
│       ├── __init__.py
│       ├── rest_api.py
│       └── web_ui.py
├── config/
│   ├── __init__.py
│   └── settings.py
├── requirements.txt
└── docker-compose.yml
```

## How to Run

### Development:
```bash
# Install dependencies
pip install -r requirements.txt

# Start the log aggregator
python app/main.py

# Or start with custom config
python app/main.py --config config/custom.yaml
```

### Production with Docker:
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f log-aggregator

# Access services:
# REST API: http://localhost:8000
# Kibana: http://localhost:5601
# Elasticsearch: http://localhost:9200
```

### Send Test Logs:
```bash
# Send syslog message
echo "<14>$(date -Iseconds) localhost app[123]: Test syslog message" | nc -u localhost 514

# Send HTTP log
curl -X POST http://localhost:8080/logs \
  -H "Content-Type: application/json" \
  -d '{"message": "Test HTTP log", "level": "INFO"}'

# Query logs via API
curl "http://localhost:8000/search?q=level:INFO&limit=10"
```

## Key Features:

1. **Multi-source Collection**: Files, syslog (UDP/TCP), HTTP endpoints
2. **Smart Parsing**: Apache, Nginx, JSON, syslog with automatic format detection
3. **Field Normalization**: Consistent field names, IP validation, severity mapping
4. **Powerful Search**: Query language with filters, time ranges, and sorting
5. **Flexible Storage**: Elasticsearch, database, and file storage options
6. **REST API**: Full-featured API for log ingestion and querying
7. **Real-time Processing**: Stream processing with minimal latency

This log aggregation system provides enterprise-grade log management capabilities that can scale from small applications to large distributed systems.
