# PTP Monitor container image
#
# Build:  docker build -t ptp-monitor .
# Run:    docker run -d --name ptp-monitor --network host \
#           --cap-add NET_RAW --cap-add NET_ADMIN ptp-monitor
#         then open http://<host>:8080
#
# Host networking is required: the monitor must see the host's real network
# interfaces to capture PTP and to join the PTP multicast groups (IGMP).
#
# The same image also runs as a central collector or a remote node:
#   docker run -d -e PTP_MODE=collector -p 8443:8443 -v ptp-data:/data ptp-monitor
#   docker run -d -e PTP_MODE=node -e PTP_INTERFACES=eth1 -e PTP_COLLECTOR_URL=... \
#           -e PTP_NODE_TOKEN=... --network host --cap-add NET_RAW --cap-add NET_ADMIN ptp-monitor
# (see docker-compose.collector.yml and docker-compose.node.yml)
FROM python:3.12-slim

LABEL org.opencontainers.image.title="PTP Monitor" \
      org.opencontainers.image.description="IEEE 1588 PTP multicast monitor with a browser dashboard" \
      org.opencontainers.image.source="https://github.com/jballanger0226/PTP-Monitor"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PTP_BUFFER_MB=128

# tcpdump brings libpcap; scapy uses them to compile the capture filter.
# iproute2 gives the interface helpers an extra way to read addresses.
# openssl creates the collector's self-signed certificate on CPUs where the
# 'cryptography' package has no ready-made wheel (e.g. 32-bit Raspberry Pi OS).
RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump iproute2 openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# scapy is pure Python and required.  psutil and cryptography are optional and are
# only installed when a binary wheel exists (arm64 and amd64 have them; 32-bit ARM may
# not, and building them from source would need a compiler); the program falls back to
# iproute2 and the openssl tool.
RUN pip install "scapy>=2.4.3" \
 && (pip install --only-binary=:all: "psutil>=5.6" || echo "psutil: no wheel, skipped") \
 && (pip install --only-binary=:all: "cryptography>=3.4" || echo "cryptography: no wheel, using openssl")

COPY ptp_monitor.py docker/entrypoint.sh docker/healthcheck.py ./
RUN chmod 0755 /app/entrypoint.sh /app/ptp_monitor.py \
 && mkdir -p /data && chmod 0700 /data

# 8080: standalone web UI.  8443: collector (HTTPS).  /data: collector accounts,
# node tokens and its generated certificate - keep it on a volume.
EXPOSE 8080 8443
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "/app/healthcheck.py"]

# Runs as root inside the container: raw packet capture needs it
# (together with the NET_RAW / NET_ADMIN capabilities).
ENTRYPOINT ["/app/entrypoint.sh"]
