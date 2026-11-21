# Backend Dockerfile — Lightweight Production Runtime
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_DEFAULT_TIMEOUT=1000 \
    PIP_RETRIES=10

# Mount host pip cache for fast resumed downloads & prevent read timeouts
COPY requirements-prod.txt requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --timeout 1000 --retries 10 -r requirements.txt

# Copy only what the API needs
COPY src/ ./backend/src/
# Copies whatever model files are present (family model is optional at runtime)
COPY models/ ./backend/models/

# Non-root user for security
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start the application
# Render injects $PORT
CMD ["sh", "-c", "uvicorn backend.src.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
