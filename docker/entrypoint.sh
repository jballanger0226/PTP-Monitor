#!/usr/bin/env bash
# Builds the ptp_monitor.py command line from environment variables.
# Anything passed to `docker run ... ptp-monitor <args>` is appended, so any
# command-line option can still be used (later options win).
#
#   PTP_HOST            web UI bind address              (default 0.0.0.0)
#   PTP_PORT            web UI port                      (default 8080)
#   PTP_INTERFACES      start capturing right away, e.g. "eth1" or "eth1,eth2"
#   PTP_BUFFER_MB       capture buffer size in MB        (default 128)
#   PTP_JOIN_DOMAIN     also join this PTP domain (uses the first interface)
#   PTP_TTL             TTL of Delay_Req packets when joining a domain
#   PTP_BPF             custom capture filter
#   PTP_NO_PROMISC      1 = do not use promiscuous mode
#   PTP_IGMP_KEEPALIVE  0 = do not re-send IGMP joins when no querier is seen
set -euo pipefail

APP="${PTP_APP:-/app/ptp_monitor.py}"
args=(--host "${PTP_HOST:-0.0.0.0}" --port "${PTP_PORT:-8080}"
      --buffer-mb "${PTP_BUFFER_MB:-128}" --no-browser)

IFS=', ' read -r -a ifaces <<< "${PTP_INTERFACES:-}"
for i in "${ifaces[@]}"; do
  if [[ -n "$i" ]]; then args+=(-i "$i"); fi
done
if [[ -n "${PTP_JOIN_DOMAIN:-}" ]]; then args+=(--join-domain "$PTP_JOIN_DOMAIN"); fi
if [[ -n "${PTP_TTL:-}" ]]; then args+=(--ttl "$PTP_TTL"); fi
if [[ -n "${PTP_BPF:-}" ]]; then args+=(--bpf "$PTP_BPF"); fi
if [[ "${PTP_NO_PROMISC:-0}" =~ ^(1|true|yes)$ ]]; then args+=(--no-promisc); fi
if [[ "${PTP_IGMP_KEEPALIVE:-1}" =~ ^(0|false|no)$ ]]; then args+=(--no-igmp-keepalive); fi

exec python "$APP" "${args[@]}" "$@"
