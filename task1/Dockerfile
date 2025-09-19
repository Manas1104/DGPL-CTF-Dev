# Dockerfile - builds and runs the vulnerable Flask app
FROM python:3.11-slim

WORKDIR /app

# Install system deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app, flags and dev folder (dev/brute.py can be removed before publishing)
COPY app.py .
COPY flags flags
COPY dev dev

# Expose port
EXPOSE 8000

ENV FLASK_ENV=production
# You can override SECRET at runtime with -e SECRET=1234
ENV SECRET=0420
ENV FLAG_PATH=flags/admin_flag.txt

# Use gunicorn for stable serving
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app", "--workers", "1", "--threads", "4"]
