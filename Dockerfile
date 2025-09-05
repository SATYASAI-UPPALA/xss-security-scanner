# Use Ubuntu as base image for security tools
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    golang-go \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set Go environment
ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

# Install Go tools
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/s0md3v/uro@latest

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY backend/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Create necessary directories
RUN mkdir -p /tmp

# Expose port
EXPOSE 8000

# Change to backend directory and start the application
WORKDIR /app/backend
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]