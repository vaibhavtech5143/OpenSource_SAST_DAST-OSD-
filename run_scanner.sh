#!/bin/bash
# Security Scanner Launcher Script (Linux/macOS)

echo "Starting SAST/DAST Security Scanner..."
echo "======================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker and try again."
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Install Python dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Installing Python dependencies..."
    python3 -m pip install -r requirements.txt
fi

# Run the security scanner
echo "Launching security scanner..."
python3 scanner.py

echo "Security scan completed. Check the output directory for results."