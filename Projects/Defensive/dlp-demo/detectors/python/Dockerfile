FROM python:3.9-slim

# Safety notice
LABEL description="DLP Demo Engine - LAB USE ONLY"
LABEL warning="Never run against production systems or real user data"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 dlpuser
USER dlpuser
WORKDIR /home/dlpuser/app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p samples/extracted logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os; exit(0 if os.getenv('DLP_LAB_MODE') == '1' else 1)"

# Entry point
ENTRYPOINT ["python", "dlp_engine.py"]
CMD ["--config", "config.json"]
