FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssl \
    curl \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY teams_webhook.py .
COPY config.conf .
COPY generate-minimal-client.sh .
COPY deploy-minimal.sh .

# Make scripts executable
RUN chmod +x generate-minimal-client.sh deploy-minimal.sh

# Create necessary directories
RUN mkdir -p clients openvpn-ca

# Expose webhook port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Set environment variables with defaults
ENV WEBHOOK_HOST=0.0.0.0
ENV WEBHOOK_PORT=5000
ENV WEBHOOK_DEBUG=False

# Run the webhook server
CMD ["python3", "teams_webhook.py"]
