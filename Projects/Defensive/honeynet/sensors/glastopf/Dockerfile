FROM python:3.9-slim

LABEL description="Glastopf Web Honeypot - FOR LAB USE ONLY"

RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash glastopf
USER glastopf

WORKDIR /home/glastopf

# Clone Glastopf
RUN git clone https://github.com/mushorg/glastopf.git .
RUN pip install --no-cache-dir -r requirements.txt

# Copy configuration
COPY glastopf.cfg etc/glastopf.cfg

EXPOSE 80

CMD ["python", "glastopf.py"]
