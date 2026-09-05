FROM python:3.11-slim

WORKDIR /app

# System dependencies for Semgrep + git cloning
RUN apt-get update && apt-get install -y \
    git curl gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep separately for better layer caching.
# The retry loop and BuildKit cache mount exist because a large wheel can time
# out mid-download on a slow or lossy link. The cache mount keeps whatever
# finished, so each retry makes forward progress instead of restarting at zero.
RUN --mount=type=cache,target=/root/.cache/pip \
    for i in 1 2 3 4 5 6; do \
        pip install --retries 10 --timeout 300 semgrep==1.75.0 && exit 0; \
        echo "semgrep install attempt $i failed; retrying in 15s..."; \
        sleep 15; \
    done; \
    exit 1

# Copy and install Python dependencies
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    for i in 1 2 3 4 5 6; do \
        pip install --retries 10 --timeout 300 -r requirements.txt && exit 0; \
        echo "requirements install attempt $i failed; retrying in 15s..."; \
        sleep 15; \
    done; \
    exit 1

# Copy application code
COPY . .

# Create temp directories used at runtime
RUN mkdir -p /tmp/reports /tmp/swarmaudit_repos

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--log-level", "info"]
