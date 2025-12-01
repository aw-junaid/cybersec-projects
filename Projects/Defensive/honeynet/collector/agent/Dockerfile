FROM python:3.11-slim

# Safety notice
LABEL description="Honeynet Sensor Agent - FOR LAB USE ONLY"
LABEL security="Requires HONEY_LAB_MODE=1 and network isolation"

# Install dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash honeynet
USER honeynet

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Create directories
RUN mkdir -p /data/artifacts /certs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080')"

CMD ["python", "app.py"]
