FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for cryptography and self-signed cert generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Generate self-signed TLS certificate for CorpSSO
RUN openssl req -x509 -newkey rsa:4096 -keyout /app/key.pem -out /app/cert.pem \
    -days 365 -nodes \
    -subj "/C=GB/ST=England/L=London/O=CorpSSO Ltd/CN=login.corpsso.local" \
    -addext "subjectAltName=DNS:login.corpsso.local,DNS:localhost"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 443

CMD ["python", "app.py"]
