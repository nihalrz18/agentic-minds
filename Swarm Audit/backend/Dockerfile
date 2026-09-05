FROM python:3.11-slim

WORKDIR /app

# System dependencies for Semgrep + git cloning
RUN apt-get update && apt-get install -y \
    git curl gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep separately for better layer caching
RUN pip install --no-cache-dir semgrep==1.75.0

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create temp directories used at runtime
RUN mkdir -p /tmp/reports /tmp/swarmaudit_repos

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--log-level", "info"]
