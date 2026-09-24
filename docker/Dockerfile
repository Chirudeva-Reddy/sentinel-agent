FROM python:3.13-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_COMPILE_BYTECODE=1

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /bin/uv

# Dependencies first (cached layer), then the project itself so its detector entry points register.
COPY pyproject.toml uv.lock README.md /app/
RUN uv sync --frozen --no-dev --no-install-project --extra server --extra dashboard
COPY sentinel/ /app/sentinel/
RUN uv sync --frozen --no-dev --no-editable --extra server --extra dashboard

ENV PATH="/app/.venv/bin:$PATH"
RUN useradd --create-home sentinel && mkdir -p /data && chown sentinel /data
USER sentinel

EXPOSE 8000 8501
CMD ["streamlit", "run", "sentinel/server/dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
