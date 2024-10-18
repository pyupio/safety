# Use the official Python 3.12 slim image
FROM python:3.12-slim

# Create a non-root user and a directory for the application
RUN useradd -m appuser && \
    mkdir /app && \
    chown appuser:appuser /app

# Set the working directory
WORKDIR /app

# Set environment variables in a single step
ENV LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    PYTHONPATH="/app"

# Install necessary dependencies, clean up after installation to reduce image size
RUN apt-get update && \
    apt-get -y install docker.io jq git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy project files into the container (relative to the build context)
COPY . /app/

# Switch to the non-root user for security reasons
USER appuser
