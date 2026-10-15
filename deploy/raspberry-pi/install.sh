#!/usr/bin/env bash
# Installs PTP Monitor natively on a Raspberry Pi (Raspberry Pi OS / Debian / Ubuntu,
# 32- or 64-bit) as a systemd service, in one of its three modes.
#
#   sudo deploy/raspberry-pi/install.sh --mode standalone|node|collector [options]
#
#   --mode MODE          standalone | node | collector            (required)
#   --prefix DIR         program files and virtual environment    (default /opt/ptp-monitor)
#   --no-apt             do not run apt-get (packages already installed)
#   --uninstall          remove the service and program (keeps /etc and /var/lib data)
#
# Settings live in /etc/ptp-monitor/ptp-monitor.env (same PTP_* variables as the container,
# see docker/entrypoint.sh). The file is only created when missing, so re-running this
# script after a git pull upgrades the program and keeps your settings.
set -euo pipefail

MODE=""; PREFIX=/opt/ptp-monitor; APT=1; UNINSTALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --no-apt) APT=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

CONF_DIR=/etc/ptp-monitor
ENV_FILE="$CONF_DIR/ptp-monitor.env"
UNIT=/etc/systemd/system/ptp-monitor.service
DATA_DIR=/var/lib/ptp-monitor
SRC="$(cd "$(dirname "$0")/../.." && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $*" >&2; exit 1; }

if [[ $UNINSTALL -eq 1 ]]; then
  systemctl disable --now ptp-monitor 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload || true
  rm -rf "$PREFIX"
  echo "Removed the service and $PREFIX. Settings ($CONF_DIR) and data ($DATA_DIR) were kept."
  exit 0
fi

case "$MODE" in standalone|node|collector) ;; *) echo "--mode must be standalone, node or collector" >&2; exit 2 ;; esac
[[ -f "$SRC/ptp_monitor.py" ]] || { echo "ptp_monitor.py not found next to this script's repository" >&2; exit 1; }

# ---- packages ---------------------------------------------------------------------
if [[ $APT -eq 1 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # tcpdump brings libpcap (capture filter); openssl makes the collector's certificate when
  # the 'cryptography' wheel is unavailable; iproute2 helps find interface addresses.
  apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
      tcpdump iproute2 openssl ca-certificates
fi

# ---- program + virtual environment ---------------------------------------------------
install -d -m 0755 "$PREFIX"
install -m 0755 "$SRC/ptp_monitor.py" "$PREFIX/ptp_monitor.py"
install -m 0755 "$SRC/docker/entrypoint.sh" "$PREFIX/entrypoint.sh"
[[ -x "$PREFIX/venv/bin/python" ]] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
# scapy is required for capture (standalone and node), pure Python. The others are optional
# and only taken as binary wheels (piwheels provides them on Raspberry Pi OS); without
# them the program uses iproute2 and the openssl tool.
if [[ $MODE != collector ]]; then
  "$PREFIX/venv/bin/pip" install --quiet "scapy>=2.4.3"
  "$PREFIX/venv/bin/pip" install --quiet --only-binary=:all: "psutil>=5.6" || echo "psutil skipped (no wheel)"
else
  "$PREFIX/venv/bin/pip" install --quiet --only-binary=:all: "cryptography>=3.4" \
    || echo "cryptography skipped (no wheel): the openssl tool will create the certificate"
fi

# ---- service account and settings ----------------------------------------------------
if [[ $MODE == collector ]]; then
  # The collector needs no raw sockets: run it as its own unprivileged user.
  id -u ptp-monitor >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin ptp-monitor
  RUN_USER=ptp-monitor
  install -d -m 0700 -o ptp-monitor -g ptp-monitor "$DATA_DIR"
else
  RUN_USER=root     # raw capture, IGMP and ports 319/320 (for joining a domain)
fi
install -d -m 0750 "$CONF_DIR"
[[ $RUN_USER == root ]] || chgrp ptp-monitor "$CONF_DIR"     # lets the collector read your own certificate

if [[ ! -f "$ENV_FILE" ]]; then
  umask 077
  case "$MODE" in
  standalone) cat > "$ENV_FILE" <<'CFG'
PTP_MODE=standalone
# The web UI has no login: it listens on this machine only. Browse it through an SSH tunnel
#   ssh -L 8080:127.0.0.1:8080 pi@raspberrypi
# or set 0.0.0.0 to serve it to a trusted LAN.
PTP_HOST=127.0.0.1
PTP_PORT=8080
# Start capturing right away (optional); otherwise choose the interface in the web UI.
#PTP_INTERFACES=eth0
PTP_BUFFER_MB=64
CFG
    ;;
  node) cat > "$ENV_FILE" <<CFG
PTP_MODE=node
# Required: where to push, and this node's token (create the node on the collector's Admin page).
PTP_COLLECTOR_URL=https://collector.example.com:8443
PTP_NODE_TOKEN_FILE=$CONF_DIR/node.token
# Required: the interface that sees PTP.
PTP_INTERFACES=eth0
# Self-signed collector certificate: pin its SHA-256 fingerprint (or use PTP_COLLECTOR_CA).
#PTP_COLLECTOR_FINGERPRINT=AA:BB:CC:...
#PTP_COLLECTOR_CA=$CONF_DIR/collector-ca.pem
PTP_BUFFER_MB=64
#PTP_NO_REMOTE_CONTROL=1
CFG
    ;;
  collector) cat > "$ENV_FILE" <<CFG
PTP_MODE=collector
PTP_HOST=0.0.0.0
PTP_PORT=8443
PTP_DATA_DIR=$DATA_DIR
# Names/IPs the self-signed certificate must be valid for (the Pi's host name and address):
#PTP_TLS_SAN=raspberrypi.local,192.168.1.50
# Your own certificate instead of a self-signed one:
#PTP_CERT=$CONF_DIR/collector.crt
#PTP_KEY=$CONF_DIR/collector.key
# First admin password (otherwise a random one is printed once in: journalctl -u ptp-monitor)
#PTP_ADMIN_PASSWORD=
CFG
    ;;
  esac
  chown root:"$([[ $RUN_USER == root ]] && echo root || echo ptp-monitor)" "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
  CREATED=1
else
  CREATED=0
  grep -q "^PTP_MODE=$MODE" "$ENV_FILE" || echo "NOTE: $ENV_FILE is set to another mode; edit PTP_MODE if you want '$MODE'."
fi

# ---- systemd unit -----------------------------------------------------------------------
if [[ $RUN_USER == root ]]; then
  CAPS="CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
  RW="ReadWritePaths=$DATA_DIR"
else
  CAPS="CapabilityBoundingSet="
  RW="ReadWritePaths=$DATA_DIR"
fi
cat > "$UNIT" <<UNIT
[Unit]
Description=PTP Monitor ($MODE)
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
Type=simple
User=$RUN_USER
EnvironmentFile=$ENV_FILE
Environment=PTP_APP=$PREFIX/ptp_monitor.py PTP_PYTHON=$PREFIX/venv/bin/python PYTHONUNBUFFERED=1
ExecStart=$PREFIX/entrypoint.sh
Restart=always
RestartSec=5
$CAPS
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
$RW

[Install]
WantedBy=multi-user.target
UNIT
mkdir -p "$DATA_DIR"      # ReadWritePaths needs it to exist (never changes an existing mode)
systemctl daemon-reload
systemctl enable ptp-monitor >/dev/null

# ---- start --------------------------------------------------------------------------------
if [[ $MODE == node && ! -s "$CONF_DIR/node.token" ]]; then
  cat <<MSG
Installed, but not started: the node needs its token and collector address.
  1. On the collector's Admin page add a node and copy its token.
  2. echo 'ptpn_...' | sudo tee $CONF_DIR/node.token >/dev/null && sudo chmod 600 $CONF_DIR/node.token
  3. sudoedit $ENV_FILE        (PTP_COLLECTOR_URL, PTP_COLLECTOR_FINGERPRINT, PTP_INTERFACES)
  4. sudo systemctl start ptp-monitor
MSG
  exit 0
fi
systemctl restart ptp-monitor
sleep 2
systemctl --no-pager --lines=5 status ptp-monitor || true
echo
echo "Settings: $ENV_FILE    Logs: journalctl -u ptp-monitor -f"
[[ $MODE == collector ]] && echo "Collector: https://$(hostname -I 2>/dev/null | awk '{print $1}'):8443   (first admin password: journalctl -u ptp-monitor | grep -i password)"
[[ $MODE == standalone ]] && echo "Web UI: http://127.0.0.1:8080 on the Pi (SSH tunnel, see the settings file)"
exit 0
