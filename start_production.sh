#!/bin/bash

# Production Startup Script for E-commerce Dashboard
# This script starts the application in production mode with Gunicorn

echo "=================================="
echo "E-commerce Dashboard - Production"
echo "=================================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found!"
    echo "Please copy .env.example to .env and configure it."
    exit 1
fi

# Load environment variables
export $(cat .env | grep -v '^#' | xargs)

# Check Redis connection
echo "Checking Redis connection..."
if ! redis-cli ping > /dev/null 2>&1; then
    echo "WARNING: Redis is not running!"
    echo "Start Redis with: sudo systemctl start redis"
    echo "Continuing without Redis (performance will be reduced)..."
fi

# Check MySQL connection
echo "Checking MySQL connection..."
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT 1" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Cannot connect to MySQL database!"
    echo "Check your .env database credentials."
    exit 1
fi

# Apply database indexes if not already applied
echo "Checking database indexes..."
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < database_indexes.sql 2>/dev/null
echo "Database indexes applied."

# Get number of CPU cores
CPU_CORES=$(nproc 2>/dev/null || echo 2)
WORKERS=$((CPU_CORES * 2 + 1))

echo ""
echo "Starting Gunicorn with $WORKERS workers..."
echo "Server will be available at: http://0.0.0.0:${PORT:-5000}"
echo ""

# Start Gunicorn
gunicorn -c gunicorn_config.py app:app

# If gunicorn exits
echo ""
echo "Server stopped."
