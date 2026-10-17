# RuleSmith: web UI + API. Works on Hugging Face Spaces (Docker, port 7860),
# Nebius Serverless Endpoints, or any container host.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    RULESMITH_RUNS_DIR=/tmp/rulesmith-runs

WORKDIR /app

# Install dependencies first so code changes do not invalidate the layer.
COPY pyproject.toml README.md ./
COPY rulesmith ./rulesmith
RUN pip install --no-cache-dir .

# Data, examples and recorded runs are read at runtime.
COPY data ./data
COPY examples ./examples

# Hugging Face Spaces runs as a non-root user with uid 1000.
RUN useradd -m -u 1000 app && mkdir -p /tmp/rulesmith-runs && chown -R app:app /app /tmp/rulesmith-runs
USER app

EXPOSE 7860
CMD ["uvicorn", "rulesmith.server.app:app", "--host", "0.0.0.0", "--port", "7860"]
