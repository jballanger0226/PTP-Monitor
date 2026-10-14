#!/usr/bin/env bash
# Builds the ptp_monitor.py command line from environment variables.
# Anything passed to `docker run ... ptp-monitor <args>` is appended, so any
# command-line option can still be used (later options win).
#
#   PTP_MODE            standalone (default) | node | collector
#
# standalone and node (capture):
#   PTP_INTERFACES      start capturing right away, e.g. "eth1" or "eth1,eth2"
#                       (required in node mode: a node has no web UI to choose in)
#   PTP_BUFFER_MB       capture buffer size in MB        (default 128)
#   PTP_JOIN_DOMAIN     also join this PTP domain (uses the first interface)
#   PTP_TTL             TTL of Delay_Req packets when joining a domain
#   PTP_BPF             custom capture filter
#   PTP_NO_PROMISC      1 = do not use promiscuous mode
#   PTP_IGMP_KEEPALIVE  0 = do not re-send IGMP joins when no querier is seen
# standalone only:
#   PTP_HOST            web UI bind address              (default 0.0.0.0)
#   PTP_PORT            web UI port                      (default 8080)
# node only:
#   PTP_COLLECTOR_URL          https://collector:8443
#   PTP_NODE_TOKEN             this node's token (or PTP_NODE_TOKEN_FILE=/run/secrets/..)
#   PTP_COLLECTOR_FINGERPRINT  pin the collector's (self-signed) certificate, SHA-256
#   PTP_COLLECTOR_CA           CA file (PEM) that signed the collector's certificate
#   PTP_PUSH_INTERVAL          seconds between pushes    (default 2)
# collector only (no capture, no special privileges needed):
#   PTP_HOST            bind address                     (default 0.0.0.0)
#   PTP_PORT            HTTPS port                       (default 8443)
#   PTP_DATA_DIR        accounts, node tokens, generated certificate (default /data)
#   PTP_CERT, PTP_KEY   your own certificate and key (PEM); without them a
#                       self-signed certificate is created in the data directory
#   PTP_TLS_SAN         extra names/IPs for the self-signed certificate, comma separated
#   PTP_ADMIN_PASSWORD  password of the first "admin" account (else a random one is
#                       printed once in the container log)
#   PTP_SESSION_HOURS   idle time before a login expires (default 12)
set -euo pipefail

APP="${PTP_APP:-/app/ptp_monitor.py}"
MODE="${PTP_MODE:-standalone}"

capture_args() {
  args+=(--buffer-mb "${PTP_BUFFER_MB:-128}" --no-browser)
  IFS=', ' read -r -a ifaces <<< "${PTP_INTERFACES:-}"
  for i in "${ifaces[@]}"; do
    if [[ -n "$i" ]]; then args+=(-i "$i"); fi
  done
  if [[ -n "${PTP_JOIN_DOMAIN:-}" ]]; then args+=(--join-domain "$PTP_JOIN_DOMAIN"); fi
  if [[ -n "${PTP_TTL:-}" ]]; then args+=(--ttl "$PTP_TTL"); fi
  if [[ -n "${PTP_BPF:-}" ]]; then args+=(--bpf "$PTP_BPF"); fi
  if [[ "${PTP_NO_PROMISC:-0}" =~ ^(1|true|yes)$ ]]; then args+=(--no-promisc); fi
  if [[ "${PTP_IGMP_KEEPALIVE:-1}" =~ ^(0|false|no)$ ]]; then args+=(--no-igmp-keepalive); fi
}

case "$MODE" in
  standalone)
    args=(--host "${PTP_HOST:-0.0.0.0}" --port "${PTP_PORT:-8080}")
    capture_args
    ;;
  node)
    # The program reads PTP_NODE_TOKEN(_FILE), PTP_COLLECTOR_CA and
    # PTP_COLLECTOR_FINGERPRINT itself, so secrets stay out of the process list.
    export PTP_NODE_STATUS_FILE="${PTP_NODE_STATUS_FILE:-/tmp/ptp_node_ok}"
    args=(--mode node --push-interval "${PTP_PUSH_INTERVAL:-2}")
    if [[ -n "${PTP_COLLECTOR_URL:-}" ]]; then args+=(--collector-url "$PTP_COLLECTOR_URL"); fi
    capture_args
    ;;
  collector)
    args=(--mode collector --host "${PTP_HOST:-0.0.0.0}" --port "${PTP_PORT:-8443}"
          --data-dir "${PTP_DATA_DIR:-/data}" --session-hours "${PTP_SESSION_HOURS:-12}")
    if [[ -n "${PTP_CERT:-}" ]]; then args+=(--cert "$PTP_CERT"); fi
    if [[ -n "${PTP_KEY:-}" ]]; then args+=(--key "$PTP_KEY"); fi
    IFS=', ' read -r -a sans <<< "${PTP_TLS_SAN:-}"
    for n in "${sans[@]}"; do
      if [[ -n "$n" ]]; then args+=(--tls-san "$n"); fi
    done
    ;;
  *)
    echo "PTP_MODE must be standalone, node or collector (got '$MODE')" >&2
    exit 2
    ;;
esac

exec python "$APP" "${args[@]}" "$@"
