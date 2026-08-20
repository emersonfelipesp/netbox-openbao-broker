# Two stages so the build toolchain does not ship. The runtime image holds an
# interpreter, the dependencies, and this package — nothing that would help an
# attacker who reached a shell inside it.
FROM python:3.12-slim AS build

WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY broker ./broker
RUN pip install --no-cache-dir .

FROM python:3.12-slim

# Unprivileged and fixed. The broker reads two certificate files and talks to
# OpenBao; it has no reason to be able to write anywhere, and `docker-compose`
# mounts its filesystem read-only.
RUN useradd --system --uid 10101 --create-home --home-dir /var/lib/broker broker

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BROKER_PORT=8201

USER broker
EXPOSE 8201

# A TCP connect, not an HTTP request. `ssl_cert_reqs=CERT_REQUIRED` applies to
# the socket rather than to a route, so an unauthenticated probe cannot finish
# the handshake even against /healthz. Checking that the port accepts a
# connection is what can honestly be checked from inside the container without
# issuing it a client certificate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,socket,sys; s=socket.create_connection(('127.0.0.1', int(os.environ['BROKER_PORT'])), 3); s.close()" || exit 1

ENTRYPOINT ["netbox-openbao-broker"]
