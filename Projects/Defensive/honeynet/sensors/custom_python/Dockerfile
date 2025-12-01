FROM python:3.11-slim

# Safety notice
LABEL description="Custom Python Honeypot - FOR LAB USE ONLY"
LABEL security="No outbound network access"

# Install dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash honeypot
USER honeypot

WORKDIR /app

# Copy application
COPY honeypot.py .

# Create log directory
RUN mkdir -p /var/log

# Security: read-only filesystem, drop capabilities
# Note: These would be specified in docker-compose or runtime

CMD ["python", "honeypot.py"]
