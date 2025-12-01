# Recon2Defend — Dockerfile (MVP)
# Lightweight Python environment for running scans + report generation

FROM python:3.11-slim

# Create working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy whole project (for offline lab)
COPY . /app/

# Default command (this will be overridden by docker-compose)
CMD ["bash"]
