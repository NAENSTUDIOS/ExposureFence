# ExposureFence — Production Multi-Stage Containerfile
# Security Hardened: Non-Root Execution, Pinned Dependencies, Minimal Attack Surface

# ---------------------------------------------------------
# Stage 1: Build Environment
# ---------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

# Install build-time OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency specifications
COPY requirements.txt .

# Install dependencies into local user directory
RUN pip install --no-cache-dir --user -r requirements.txt

# ---------------------------------------------------------
# Stage 2: Runtime Production Image
# ---------------------------------------------------------
FROM python:3.12-slim-bookworm AS runner

LABEL maintainer="NAENSTUDIOS" \
      platform="ExposureFence" \
      version="2.0.0-hardened" \
      description="AWS Cloud Security Governance & AI-Assisted Response Assurance Platform"

WORKDIR /app

# Install minimal runtime dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Security: Create unprivileged system group and user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

# Copy installed Python packages from builder
COPY --from=builder /root/.local /app/.local

# Set runtime environment variables
ENV PATH="/app/.local/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    EXPOSUREFENCE_DATA_MODE=mock \
    EXPOSUREFENCE_DB_PATH=/app/exposurefence.db \
    EXPOSUREFENCE_AUDIT_PATH=/app/audit.jsonl \
    AWS_DEFAULT_REGION=us-east-1

# Copy application source and assets
COPY --chown=appuser:appgroup backend /app/backend
COPY --chown=appuser:appgroup dashboard /app/dashboard
COPY --chown=appuser:appgroup rules /app/rules
COPY --chown=appuser:appgroup mock_data /app/mock_data
COPY --chown=appuser:appgroup agent /app/agent
COPY --chown=appuser:appgroup security /app/security
COPY --chown=appuser:appgroup docs /app/docs
COPY --chown=appuser:appgroup README.md /app/README.md

# Pre-populate empty databases / logs if not mounted
RUN touch /app/exposurefence.db /app/audit.jsonl && \
    chown -R appuser:appgroup /app

# Switch to unprivileged execution user
USER appuser:appgroup

# Container Health Probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose HTTP API & Dashboard Port
EXPOSE 8000

# Start ExposureFence Server
CMD ["python", "-m", "backend.server", "8000"]
