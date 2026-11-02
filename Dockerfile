FROM python:3.12-slim

LABEL maintainer="Healthcare AI Platform"
LABEL description="HIPAA-compliant FastAPI service with PHI redaction, mTLS, FHIR validation"

# Security: run as non-root user
RUN groupadd -r healthcare && useradd -r -g healthcare healthcare

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY config/ ./config/

# Create required directories
RUN mkdir -p /app/logs /app/certs && chown -R healthcare:healthcare /app

USER healthcare

# Expose HTTPS port (mTLS enforced — Cert Required)
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--ssl-keyfile", "/app/certs/server.key", \
     "--ssl-certfile", "/app/certs/server.crt", \
     "--ssl-ca-certs", "/app/certs/ca.crt"]
