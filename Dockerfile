# Dockerfile — ZeroTrustBackend (Layer 3: Ashish)
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .
COPY scripts/docker_migrate.sh ./scripts/docker_migrate.sh
COPY scripts/seed_admin.py ./scripts/seed_admin.py


# Copy Uthkarsh's compiled C engine
COPY libriskscore.so /app/libriskscore.so

COPY model.isof /app/model.isof

# Make migration script executable
RUN chmod +x scripts/docker_migrate.sh

# Environment variable for .so path inside container
ENV SO_PATH=/app/libriskscore.so

# Expose FastAPI port
EXPOSE 8000

# Start: wait for DB, run migrations, then start server
CMD ["sh", "-c", "scripts/docker_migrate.sh && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"]