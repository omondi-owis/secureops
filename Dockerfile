# SecureOps — production image
# Build:  docker build -t secureops:latest .

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Nmap is required for the authorized network scanner.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as a non-root user.
RUN useradd --create-home --uid 1001 secureops \
    && chown -R secureops:secureops /app
USER secureops

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://127.0.0.1:8000/api/wazuh/status -o /dev/null || exit 1

# Single worker: the SOC loop and SSE feeds are designed for one process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
