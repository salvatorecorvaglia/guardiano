# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# Pinned, hash-checked dependencies (see README.md for lock-file regeneration).
COPY requirements.lock requirements-dev.lock ./
ARG INSTALL_DEV=false
RUN if [ "$INSTALL_DEV" = "true" ]; then LOCK=requirements-dev.lock; else LOCK=requirements.lock; fi \
 && pip install --require-hashes -r "$LOCK"

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000 \
    WEB_CONCURRENCY=4 \
    FORWARDED_ALLOW_IPS="127.0.0.1"
# FORWARDED_ALLOW_IPS above decides whose X-Forwarded-For is believed. Loopback only by default: the
# client address it yields is what the login rate limit and the audit log are keyed on, so trusting
# every peer would let anyone who reaches this container directly forge both. The bundled stack
# widens it in docker-compose.yml, where nginx overwrites the header with the real peer address.
RUN groupadd --system --gid 10001 guardiano \
 && useradd --system --uid 10001 --gid guardiano --home /app --shell /usr/sbin/nologin guardiano \
 && mkdir -p /app && chown guardiano:guardiano /app
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=guardiano:guardiano app ./app
COPY --chown=guardiano:guardiano pyproject.toml entrypoint.sh ./
RUN chmod +x entrypoint.sh
USER guardiano
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/readyz',timeout=2)" || exit 1
ENTRYPOINT ["./entrypoint.sh"]
CMD ["serve"]
