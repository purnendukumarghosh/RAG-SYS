# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY nimbusvpn ./nimbusvpn
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.title="NimbusVPN" \
      org.opencontainers.image.description="Cloud-based secure VPN: WireGuard + hardened control plane"

# wireguard-tools: wg / wg-quick; iproute2 + iptables: interface, routing and NAT setup.
RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NIMBUS_DATA_DIR=/data \
    NIMBUS_RUNTIME_DIR=/run/nimbusvpn \
    NIMBUS_HOST=0.0.0.0 \
    NIMBUS_PORT=8000

VOLUME ["/data"]
EXPOSE 8000/tcp 51820/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status != 200)"

# Runs as root inside the container because managing a network interface needs
# CAP_NET_ADMIN; docker-compose grants only that capability (plus NET_RAW for iptables).
CMD ["python", "-m", "nimbusvpn", "serve"]
