# =============================================
# MIRAGE ML-WAF Docker Image
# =============================================
# Multi-stage build for minimal image size
# Optimized for runtime (training data excluded via .dockerignore)

# =============================================
# Stage 1: Builder - Compile Python dependencies
# =============================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================
# Stage 2: Runtime - Minimal production image
# =============================================
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install runtime dependencies (curl for healthcheck, jq/bc for test scripts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    bc \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos '' wafuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code (excluding payloads via .dockerignore)
# NOTE: Training data (data/payloads/) is excluded - models are pre-trained
COPY --chown=wafuser:wafuser . .

# Create necessary runtime directories
RUN mkdir -p \
    /app/logs \
    /app/models \
    /app/data/feedback \
    /app/data/adaptive \
    /app/data/audit \
    /app/data/security \
    && chown -R wafuser:wafuser /app

# Remove any accidentally copied payload data (backup cleanup)
RUN rm -rf /app/data/payloads 2>/dev/null || true

# Switch to non-root user for security
USER wafuser

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ENV=production
ENV HOST=0.0.0.0
ENV PORT=8080
ENV WORKERS=4

# Expose ports
EXPOSE 8080 9090

# Health check — the standalone WAF exposes /waf/health
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/waf/health || exit 1

# Run the standalone layered WAF under gunicorn (production WSGI server).
# NOT `flask run` / `app.run()` — that is Werkzeug's development server: single-process,
# no request queueing, and explicitly not for production traffic.
#
# --workers: CPU-bound scoring, so processes not threads. Override with WORKERS.
# --threads 2: lets a worker overlap the upstream proxy wait (I/O) with scoring.
# --timeout 30: a request that takes longer than this is a bug; kill the worker.
# --preload: load models ONCE before forking -> workers share the read-only pages,
#            so N workers do not cost N model copies.
CMD ["sh","-c","exec gunicorn waf.server:app \
  --bind 0.0.0.0:${PORT:-8080} \
  --workers ${WORKERS:-4} \
  --threads 2 \
  --timeout 30 \
  --graceful-timeout 20 \
  --keep-alive 5 \
  --preload \
  --access-logfile - --error-logfile - \
  --worker-tmp-dir /dev/shm"]
