# Use Python 3.11 slim image for smaller footprint
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for networking
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN groupadd -r mdnsfw && useradd -r -g mdnsfw mdnsfw

# Set permissions for the app directory
RUN chown -R mdnsfw:mdnsfw /app

# Create volume mount point for permissions file
VOLUME ["/app/data"]

# Expose ports
EXPOSE 5353/udp 9080/tcp

# Set environment variables with defaults
ENV MDNS_PORT=5353 \
    MDNS_ADDRESS=224.0.0.251 \
    WEB_PORT=9080 \
    WEB_HOST=0.0.0.0 \
    PERMISSIONS_FILE=/app/data/permissions.yaml \
    LOG_LEVEL=INFO \
    LISTEN_IPS=""

# Switch to non-root user
USER mdnsfw

# Health check to ensure both services are running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9080/ || exit 1

# Run the application
CMD ["python", "main.py"]