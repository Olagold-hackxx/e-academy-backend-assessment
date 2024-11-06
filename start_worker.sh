#!/bin/bash

# Activate virtual environment if you have one
# source /path/to/venv/bin/activate
# Start Celery worker in the background

echo "Starting Celery worker..."
celery -A e_academy worker --loglevel=info