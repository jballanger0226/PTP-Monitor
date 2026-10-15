# Running PTP Monitor on a Raspberry Pi

All three modes run on a Raspberry Pi: **standalone** (web UI on the Pi), **node** (captures PTP
and pushes to a collector) and **collector** (the central web front end with logins and HTTPS).
You can run them natively as a systemd service (an installer is provided) or as a container.

> **Status.** The installer, the service unit and the ARM images are checked in CI or in a
> simulated environment (section 8), but the author has not run them on a physical Pi.
> Capture, IGMP and PTP behaviour on real Pi network hardware is therefore unverified.

## 1. Hardware and OS

| | |
|---|---|
| Models | Pi 3, 4, 5, Zero 2 W (64-bit OS), and any Pi with 32-bit Raspberry Pi OS (Pi 2, Zero, 1 work but are slow). |
| OS | Raspberry Pi OS (Bullseye or newer) or Debian/Ubuntu for ARM. Python 3.8+ is needed and included. |
| Architecture | `aarch64` (64-bit) and `armv7l` (32-bit) are both supported. Check with `uname -m`. |
| RAM | Node: 512 MB is enough with `PTP_BUFFER_MB=32`. Standalone/collector: 1 GB or more recommended. |
| Network | Use **wired Ethernet**. Wi-Fi drivers often do not deliver multicast or promiscuous traffic reliably. |
| Storage | A good SD card (or SSD/USB boot). The collector writes small files to its data directory only when accounts, nodes or sessions change. |
| Time | Make sure the clock is correct (NTP) before the first collector start, so its certificate dates are right. The service waits for `time-sync.target`. |

## 2. Native install (systemd)

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/jballanger0226/PTP-Monitor.git
cd PTP-Monitor
sudo deploy/raspberry-pi/install.sh --mode collector        # or node, or standalone
```

The script installs the apt packages (`python3-venv`, `tcpdump`/libpcap, `openssl`, `iproute2`),
puts the program and a virtual environment in `/opt/ptp-monitor`, writes the settings file
`/etc/ptp-monitor/ptp-monitor.env` (only if missing), installs and starts the
`ptp-monitor` service. Re-run it after `git pull` to upgrade: your settings are kept.
Python packages come from PyPI/piwheels as ready-made binary wheels; a package without a wheel
for your CPU is skipped and the program falls back (`psutil` → `ip`, `cryptography` → `openssl`).

The service runs as **root** in standalone and node mode (raw capture, IGMP, ports 319/320) with a
restricted capability set, and as the unprivileged user `ptp-monitor` in collector mode.

### Collector

```bash
sudo deploy/raspberry-pi/install.sh --mode collector
sudoedit /etc/ptp-monitor/ptp-monitor.env      # set PTP_TLS_SAN=raspberrypi.local,<the Pi's IP>
# (set it before the first start, or delete the generated collector.crt/.key in /var/lib/ptp-monitor)
sudo systemctl restart ptp-monitor
journalctl -u ptp-monitor | grep -i -E "password|fingerprint"
```

Open `https://<pi>:8443`, sign in as `admin` with the printed password (you must change it), and
add nodes on the Admin page. The log also shows the certificate fingerprint your nodes pin. Your
own certificate: set `PTP_CERT` / `PTP_KEY` in the settings file (readable by the group
`ptp-monitor`). Open TCP 8443 in your firewall if the Pi has one (`sudo ufw allow 8443/tcp`).
Everything else about users, tokens and security is in the main README.

### Node

```bash
sudo deploy/raspberry-pi/install.sh --mode node      # installs, does not start yet
echo 'ptpn_PASTE-TOKEN' | sudo tee /etc/ptp-monitor/node.token >/dev/null
sudo chmod 600 /etc/ptp-monitor/node.token
sudoedit /etc/ptp-monitor/ptp-monitor.env            # PTP_COLLECTOR_URL, PTP_COLLECTOR_FINGERPRINT, PTP_INTERFACES=eth0
sudo systemctl start ptp-monitor
```

The node only connects out to the collector (HTTPS 8443); it opens no port. It appears online on
the collector within seconds. `PTP_NO_REMOTE_CONTROL=1` stops the collector from making it join
a PTP domain. A node that restarts leaves any joined domain; set `PTP_JOIN_DOMAIN=0` to rejoin
at start.

### Standalone

```bash
sudo deploy/raspberry-pi/install.sh --mode standalone
ssh -L 8080:127.0.0.1:8080 pi@raspberrypi            # from your computer, then browse http://127.0.0.1:8080
```

The standalone UI has no login, so the service listens on the Pi itself only
(`PTP_HOST=127.0.0.1`). Set `PTP_HOST=0.0.0.0` only on a trusted network, or use the SSH tunnel.

### Day to day

```bash
systemctl status ptp-monitor            journalctl -u ptp-monitor -f
sudoedit /etc/ptp-monitor/ptp-monitor.env && sudo systemctl restart ptp-monitor
sudo deploy/raspberry-pi/install.sh --uninstall      # keeps /etc/ptp-monitor and /var/lib/ptp-monitor
```

All settings are the same `PTP_*` variables as for the container; the list is at the top of
`docker/entrypoint.sh` and in the README.

## 3. Container

Install Docker with Docker's own script or package repository (see docs.docker.com/engine/install),
then use the published multi-arch image (it selects `arm64` or `arm/v7` itself):

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER            # log out and in again

# collector
docker run -d --name ptp-collector --restart unless-stopped -p 8443:8443 \
  -v ptp-collector-data:/data -e PTP_MODE=collector \
  -e PTP_TLS_SAN=raspberrypi.local,192.168.1.50 ghcr.io/jballanger0226/ptp-monitor:latest

# node (host networking: it must see the Pi's real interface)
docker run -d --name ptp-node --restart unless-stopped --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN -e PTP_MODE=node -e PTP_INTERFACES=eth0 \
  -e PTP_COLLECTOR_URL=https://collector.example.com:8443 -e PTP_NODE_TOKEN=ptpn_... \
  -e PTP_COLLECTOR_FINGERPRINT=AA:BB:... -e PTP_BUFFER_MB=32 ghcr.io/jballanger0226/ptp-monitor:latest

# standalone
docker run -d --name ptp-monitor --restart unless-stopped --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN ghcr.io/jballanger0226/ptp-monitor:latest
```

The compose files `docker-compose.collector.yml` and `docker-compose.node.yml` work unchanged
(`docker compose -f ... up -d`). Until the first image is published from `main`, build it on the
Pi: `docker build -t ptp-monitor .` (use `image: ptp-monitor:latest`). The standalone container UI
is published on port 8080 without a login; keep it on a trusted network.

## 4. Where to put the Pi

A Pi has one Ethernet port, so the capture interface and the management/push path are the same
port. That is fine for a node that only needs the PTP traffic its port receives or
that joins a domain itself (*Join domain* on the collector, which sends the IGMP joins). To
watch **other** devices' PTP traffic passively, connect the Pi to a switch **mirror (SPAN)
port**, or add a second (USB) Ethernet adapter and set `PTP_INTERFACES` to that adapter
(`eth1`) while `eth0` carries the push.

## 5. Accuracy: what a Pi can and cannot say

The Pi timestamps packets in software, not in hardware. The monitor shows whether PTP messages
arrive, from whom, with what intervals, announce data and BMCA ranking, and a software-based
offset/delay estimate when the Pi joins as a slave. Treat that estimate as indicative (tens to
hundreds of microseconds of jitter, more on a busy Pi or a Pi 3's USB-attached Ethernet), not as a
replacement for a hardware-timestamping analyser.

## 6. Tuning

* `PTP_BUFFER_MB` (default 128 in the image, 64 in the native settings file): lower it on small Pis.
* High PTP rates plus several interfaces on a Pi Zero or Pi 3 can drop packets; capture one
  interface, and use a BPF filter (`PTP_BPF`) if the port carries much non-PTP traffic.
* Use a 64-bit OS on Pi 3/4/5 where possible: more Python wheels are ready-made and it is faster.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `install.sh`: pip errors | Offline Pi or piwheels unreachable; check internet access. A missing optional wheel is skipped, scapy must install. |
| "This program needs scapy" | Standalone/node: scapy missing from the venv: `/opt/ptp-monitor/venv/bin/pip install scapy`. |
| Collector: "Cannot create a self-signed certificate" | Install `openssl` (`sudo apt-get install openssl`) or the `cryptography` wheel, or set `PTP_CERT`/`PTP_KEY`. |
| Browser/node says the certificate is invalid for the name | Add the Pi's name/IP to `PTP_TLS_SAN`, delete the generated `collector.crt/key` in `/var/lib/ptp-monitor`, restart, and give nodes the new fingerprint. |
| Certificate "not yet valid" | The Pi's clock was wrong when it was created. Fix time sync, delete the generated certificate and restart. |
| Node never online | Wrong URL/token/fingerprint or port 8443 blocked; `journalctl -u ptp-monitor` names the error. |
| Online but no packets | Wrong `PTP_INTERFACES`, Wi-Fi instead of Ethernet, no mirror port, or the switch does not forward PTP multicast to the Pi (use *Join domain*). |
| Container: no capture | Needs `--network host` and `--cap-add NET_RAW --cap-add NET_ADMIN`. |
| Out of memory kills | Lower `PTP_BUFFER_MB` enabling some swap can also help on 512 MB models. |

## 8. What was verified

* CI builds the image for `linux/arm64` and `linux/arm/v7` (emulated), reports which optional
  packages are present, and runs the collector end-to-end test and a standalone start on ARM.
* `install.sh` and the systemd unit were exercised in a sandbox with stubbed `pip`/`systemctl`
  (file layout, permissions, the unit passes `systemd-analyze verify`), and the collector started
  through the same `entrypoint.sh` the service uses.
* Not verified: real Pi hardware, real packet capture and IGMP on the Pi's NIC, `pip` on
  Raspberry Pi OS, and the service under a real systemd.
