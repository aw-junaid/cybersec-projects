FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -s /bin/false icsuser
USER icsuser

# Safety check on startup
COPY ../scripts/safety/check_isolated.py .
RUN python check_isolated.py

CMD ["python", "server.py"]
