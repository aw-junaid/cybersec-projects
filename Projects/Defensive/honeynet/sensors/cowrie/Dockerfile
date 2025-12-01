FROM python:3.11-slim

LABEL description="Cowrie SSH/Telnet Honeypot - FOR LAB USE ONLY"

RUN apt-get update && apt-get install -y \
    git \
    libssl-dev \
    libffi-dev \
    build-essential \
    libpython3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash cowrie
USER cowrie

WORKDIR /home/cowrie

# Clone Cowrie
RUN git clone https://github.com/cowrie/cowrie .
RUN pip install --no-cache-dir -r requirements.txt

# Copy configuration
COPY cowrie.cfg etc/cowrie.cfg

# Create necessary directories
RUN mkdir -p log/ var/lib/cowrie/

# Security: Run as non-root, read-only config
EXPOSE 2222 2223

CMD ["bin/cowrie", "start", "-n"]
