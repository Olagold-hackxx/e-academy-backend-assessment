#!/bin/bash

# Activate virtual environment if you have one
# source /path/to/venv/bin/activate

# Start Django server in the background
echo "Starting Django server..."
python manage.py runserver 0.0.0.0:8000 &

# Start Celery worker in the background
echo "Starting Celery worker..."
celery -A e_academy worker --loglevel=info

