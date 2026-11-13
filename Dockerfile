# ============================================================
# Dockerfile - نظام المرتبات الشامل (Payroll System)
# ============================================================

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5003 \
    HOST=0.0.0.0 \
    PAYROLL_NO_BROWSER=1 \
    TZ=Africa/Cairo

# Install system dependencies (curl for healthcheck, fonts for Arabic PDF generation, tzdata for timezone)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    fonts-dejavu-core \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition first for layer caching
COPY requirements.txt .

# Upgrade pip and install Python packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Create directory for backups and logs
RUN mkdir -p /app/backups /app/logs

# Expose the application port
EXPOSE 5003

# Healthcheck to monitor container availability
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5003/login || exit 1

# Production WSGI server (Gunicorn)
CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "3", "--threads", "2", "--timeout", "120", "app:app"]

