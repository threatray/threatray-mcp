# syntax=docker/dockerfile:1
# check=error=true
ARG VERSION=3.13
FROM python:${VERSION}-slim AS builder
LABEL maintainer="Threatray <support@threatray.com>"

ENV VIRTUAL_ENV=/app/venv \
    PATH="/app/venv/bin:$PATH" \
    UV_CACHE_DIR=/tmp/.uv_cache \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN mkdir -p /app && \
    python -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir uv

WORKDIR /app

FROM builder AS lock

COPY pyproject.toml README.md /app/
RUN /app/venv/bin/uv pip compile pyproject.toml --extra dev --universal --upgrade -o uv.lock

FROM builder AS base

COPY pyproject.toml uv.lock README.md /app/
RUN --mount=type=cache,target=/tmp/.uv_cache \
    /app/venv/bin/uv pip install -r pyproject.toml --extra dev

FROM python:${VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/app/venv/bin:$PATH

COPY --from=base /app/venv /app/venv
COPY . /app/

WORKDIR /app

# Declarative only — the default port for the optional HTTP transport
# (THREATRAY_TRANSPORT=http). stdio (the default) ignores it.
EXPOSE 8000

CMD ["python", "-m", "threatray_mcp"]
