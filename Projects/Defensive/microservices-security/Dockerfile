FROM python:3.11-slim

WORKDIR /app

RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/python/service_a.py .

USER app

EXPOSE 8080

CMD ["python", "service_a.py"]
