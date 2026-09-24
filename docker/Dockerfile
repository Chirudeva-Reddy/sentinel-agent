FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install uv package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency specifications
COPY pyproject.toml /app/

# Install dependencies using uv
RUN uv venv /app/.venv && uv sync --no-dev

# Copy source code and documentation
COPY sentinel/ /app/sentinel/
COPY examples/ /app/examples/
COPY README.md /app/

ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8000 8501

# Default command: launch Sentinel incident dashboard
CMD ["streamlit", "run", "sentinel/server/dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
