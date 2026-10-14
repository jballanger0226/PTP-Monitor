# PTP Monitor (`ptp_monitor.py`)

A single-file Python tool for watching IEEE 1588 Precision Time Protocol (PTP) traffic on a network. Pick one or more wired interfaces and it joins the PTP multicast groups and captures every PTP packet. It then shows everything live in a browser dashboard: message rates, the hosts sending Sync, the clocks ranked by the Best Master Clock Algorithm, who is clocking off whom, and Delay_Req behaviour.

It can also join a PTP domain as a measurement-only slave and chart the clock corrections it would apply. The capture can be downloaded as a `.pcap` for Wireshark at any time.

- One Python file, one dependency (scapy).
- Runs on Linux, macOS and Windows.
- The web UI is served by the program itself and opens in your browser automatically.
- It only listens and measures. It never changes this computer's clock.
- **Standalone or distributed.** By default one program captures and serves its own dashboard. Alternatively, run headless **nodes** at several sites that report to one central **collector** with an HTTPS web UI and user login. See [Collector and nodes](#collector-and-nodes).

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Running in a container](#running-in-a-container)
- [Collector and nodes](#collector-and-nodes)
- [Command-line options](#command-line-options)
- [The dashboard, section by section](#the-dashboard-section-by-section)
- [Exports](#exports)
- [Capture buffer](#capture-buffer)
- [HTTP API](#http-api)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

---

## Features

**Capture**
- Interface picker that shows only *active wired* interfaces by default. It hides Wi-Fi, cellular, VPN/tunnel (WireGuard, utun, tun/tap, ZeroTier, etc.), link-down and loopback interfaces, including macOS `awdl0`/`llw0`. "Show all interfaces (advanced)" lists the hidden ones as well, each tagged with why it was hidden.
- Each interface shows its IPv4 address, MAC and link state, each in its own colour.
- Joins the PTP multicast groups **224.0.1.129 – 224.0.1.132** (IGMP) on every selected interface.
- Captures PTP over UDP (event port 319, general port 320) and Layer-2 PTP (EtherType `0x88F7`, VLAN-tagged too), plus IGMP so the joins can be checked.
- **Multicast membership check**: per interface, whether the operating system really joined each PTP group, whether this computer's IGMP join reports went out on the wire, and whether the network has an IGMP querier. It also gives plain-language hints when no PTP packets arrive.
- **Join keep-alive**: re-sends the joins every 60 s when no IGMP querier is seen, so switches with IGMP snooping keep forwarding PTP. A join that failed (for example because the interface had no IPv4 address yet) is retried automatically every 10 s.
- Decodes PTPv2 fully and PTPv1 at a basic level.

**Live statistics**
- Overview boxes: PTP messages captured, messages per second, total throughput received, current bandwidth, hosts sending Sync, capture time.
- Messages-per-second chart (last 5 minutes) and a total-by-message-type bar chart.
- Per-second rate chart for all message types. Click a type in the legend to turn it on or off.
- A card for every message type with its own chart. Each card shows total, messages/s now, and per-second min, max and average (zero values are hidden).

**Clocks and hosts**
- **Hosts sending Sync**: grouped by domain under collapsible headers. Each host gets a role badge (Grandmaster / Boundary clock / Master). Boundary clocks are indented under the grandmaster they follow, and each grandmaster can be collapsed. Columns: announced vs. observed Sync interval, Sync/s implied by the interval, measured Sync/s, measured total messages/s, packet counts and last seen.
- **Announce / BMCA ranking**: every clock sending Announce, ranked per domain using the IEEE 1588 data-set comparison. Rank 1 is the current grandmaster and the rows below it are its successors in order, each with the reason it ranks below the clock above. Boundary clocks are left out, because they only relay the true grandmaster. Expired and ineligible clocks are marked, and master changes are logged.
- **Clock hierarchy**: a per-domain tree of every PTP device and the clock it is clocking off (grandmaster → boundary clocks → slaves). Each link shows how it was worked out, and any subtree can be collapsed. **Searchable** by IP address, clock identity or MAC address.
- **MAC address from clock identity**: when a clock identity was built from a MAC address (the IEEE 1588 form `aa:bb:cc:FF:FE:dd:ee:ff`), the MAC (`aa:bb:cc:dd:ee:ff`) is shown next to it in every table and in the CSV.
- **Delay_Req interval check**: hosts whose measured Delay_Req interval differs from their domain grandmaster's Sync interval. The table can be downloaded as CSV.

**Taking part in a domain (optional)**
- Acts as a slave-only ordinary clock in a chosen domain (0–127). It follows the best master, sends Delay_Req messages and computes offset and path delay (end-to-end mechanism).
- Charts the correction and path delay of every measurement, with a mean ± 2σ band. A statistics table shows Max, Min, Average, Median, 1σ, 2σ, and the count and percentage of corrections outside mean ± 2σ.
- Shows the time the grandmaster is giving the device, in **UTC** and **TAI**.
- Delay_Req rate, multicast or unicast, IP TTL (1–255), local timescale and "only follow this master IP" can all be set.

**Packets and exports**
- Captured-packet list (newest first) with type and text filters, a pause switch, and a **DSCP** column with standard names (EF, CS7, AF41, etc.).
- **Download .pcap** of the whole capture (classic pcap format, opens in Wireshark and tcpdump).
- **Download CSV** of the Delay_Req interval check.
- Configurable **capture buffer** that rolls over the oldest packets when full.

**Convenience**
- Opens the dashboard in your browser on start-up. Under `sudo` it opens as your normal user, not as root.
- If port 8080 is busy, the next free port is used automatically.
- Collapsed sections and domains are remembered per browser.
- **Light, Dark or System theme**, chosen with the switch at the top right and remembered per browser. "System" follows the computer's light / dark setting, live.

---

## Requirements

| | |
|---|---|
| Python | 3.8 or newer |
| Python packages | `scapy` (required, 2.4.3 or newer), `psutil` (optional, extra way to find interface IP addresses) – see `requirements.txt` |
| Privileges | Raw packet capture and the IGMP join need **root / Administrator** |
| Linux | Run with `sudo` (or give Python `CAP_NET_RAW` + `CAP_NET_ADMIN`) |
| macOS | Run with `sudo`. libpcap is built in |
| Windows | Install **[Npcap](https://npcap.com/)** and run from an **elevated** (Run as administrator) prompt |
| Browser | Any current browser (Chrome, Edge, Firefox, Safari) |

---

## Installation

Because the program runs as root, install the packages for the **same Python interpreter you will start with `sudo`**. A virtual environment is the easiest way, and is required on systems with an "externally managed" system Python (recent macOS Homebrew, Debian/Ubuntu).

**Linux / macOS**

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
sudo ./venv/bin/python ptp_monitor.py
```

Or, for the system Python:

```bash
sudo python3 -m pip install -r requirements.txt
sudo python3 ptp_monitor.py
```

**Windows** (elevated PowerShell or Command Prompt, after installing Npcap)

```powershell
py -m pip install -r requirements.txt
py ptp_monitor.py
```

> Installing with `pip install --user` and then running with `sudo` is a common trap: root cannot see packages installed in your user's site-packages. The program then stops with "This program needs scapy".

---

## Quick start

1. Start it: `sudo python3 ptp_monitor.py`. The dashboard opens at `http://127.0.0.1:8080`.
2. In **1. Choose interface(s) to enable**, tick the interface(s) on the PTP network and press **Start capture**.
3. Watch the overview boxes, charts and tables fill in. Click domain headers to collapse them.
4. Optionally, in **2. Participate in a PTP domain**, choose a domain and press **Join domain** to start measuring corrections.
5. Press **Download .pcap** at any time to save the capture.

Other ways to start:

```bash
sudo python3 ptp_monitor.py --port 9000                  # different port
sudo python3 ptp_monitor.py -i eth1 -i eth2              # start capturing right away
sudo python3 ptp_monitor.py -i eth1 --join-domain 0 --ttl 16   # capture + join domain 0
sudo python3 ptp_monitor.py --buffer-mb 512              # bigger capture buffer
sudo python3 ptp_monitor.py --host 0.0.0.0 --no-browser  # headless box, reach the UI remotely
```

Stop with **Ctrl+C**. The capture stops and the multicast groups are left.

---

## Running in a container

The repository includes a `Dockerfile` and a `docker-compose.yml`. The image contains everything the monitor needs: Python 3.12, scapy, psutil, libpcap and tcpdump.

> **Linux hosts only for real captures.** The container must use **host networking** to see the machine's physical interfaces and join the PTP multicast groups on them. On macOS and Windows, Docker runs inside a virtual machine, so even with host networking the container sees the VM's network, not your Mac's or PC's Ethernet ports. On a Mac, run `ptp_monitor.py` directly as described above.

**With Docker Compose** (from the repository folder):

```bash
docker compose up -d --build
# then open http://<host>:8080
```

**With plain Docker:**

```bash
docker build -t ptp-monitor .
docker run -d --name ptp-monitor --restart unless-stopped \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PTP_INTERFACES=eth1 \
  ptp-monitor
```

**Published image.** The GitHub Actions workflow (`.github/workflows/container.yml`) builds and smoke-tests the image on every pull request. On every push to `main` (and on `v*` tags) it publishes a multi-architecture image (`linux/amd64`, `linux/arm64`) to the GitHub Container Registry:

```bash
docker pull ghcr.io/jballanger0226/ptp-monitor:latest
```

The package is private like the repository. Run `docker login ghcr.io` with a token that has `read:packages`, or make the package public in its GitHub settings.

The image runs standalone by default. `PTP_MODE=collector` or `PTP_MODE=node` runs it as a central collector or a headless remote node instead ([Collector and nodes](#collector-and-nodes)); the variables below are for standalone, and the node and collector variables are listed in that section.

**Configuration** is done with environment variables. Any `ptp_monitor.py` option can also be appended after the image name, for example `docker run … ptp-monitor --ttl 16`; later options win.

| Variable | Default | Meaning |
|---|---|---|
| `PTP_HOST` | `0.0.0.0` | Web UI bind address. With host networking, `127.0.0.1` makes it reachable from the host only. |
| `PTP_PORT` | `8080` | Web UI port (on the host, because of host networking) |
| `PTP_INTERFACES` | – | Start capturing right away, e.g. `eth1` or `eth1,eth2`. Leave empty to choose in the web UI. |
| `PTP_BUFFER_MB` | `128` | Capture buffer size |
| `PTP_JOIN_DOMAIN` | – | Also join this PTP domain on the first interface |
| `PTP_TTL` | – | TTL of the Delay_Req packets when joining a domain |
| `PTP_BPF` | – | Custom capture filter |
| `PTP_NO_PROMISC` | `0` | `1` = don't use promiscuous mode |
| `PTP_IGMP_KEEPALIVE` | `1` | `0` = don't re-send IGMP joins when no querier is seen |

Notes:
- **Privileges:** the container runs as root and needs `NET_RAW` (packet capture) and `NET_ADMIN` (promiscuous mode). It does not need `--privileged`.
- **Access:** the web UI has no authentication and listens on all addresses by default. Put it on a management network, set `PTP_HOST=127.0.0.1`, or firewall the port.
- **Health:** a health check runs every 30 s (`docker ps` shows *healthy*). Standalone: the web UI answers `/api/state`. The collector and node modes have their own checks, see [Collector and nodes](#collector-and-nodes).
- **No browser:** the container never tries to open a browser.
- **Persistence:** all data lives in memory. Download the `.pcap` or CSV from the web UI to keep it.

---

## Collector and nodes

For more than one network, run one **collector** and a **node** at each site instead of a standalone program everywhere.

```
 site A:  node ──┐   capture + analysis, no web UI,
 site B:  node ──┼─► outbound HTTPS push (per-node token) ──►  collector  ◄── your browser
 site C:  node ──┘                                    https://collector:8443  (login)
```

| | Standalone (default) | Node | Collector |
|---|---|---|---|
| Start with | `ptp_monitor.py` | `--mode node` | `--mode collector` |
| Captures PTP | yes | yes | no |
| Needs root / scapy / Npcap | yes | yes | **no** |
| Web UI | HTTP, no login | **none** | **HTTPS, local user login** |
| Listens on a port | 8080 | **none** (connects out) | 8443 |

Standalone is unchanged: everything described elsewhere in this README still applies to it. The node runs the same capture and analysis, so each node's dashboard on the collector is the **same page** you get standalone (charts, hosts, BMCA ranking, hierarchy, Delay_Req check, IGMP membership, joined-domain measurement), with a bar on top that shows the node and whether it is online. The capture itself (interfaces, start/stop, buffer) is controlled on the node, but an admin can make the node **join a PTP domain** from the collector (see [Joining a PTP domain from the collector](#joining-a-ptp-domain-from-the-collector)).

### Set up the collector

```bash
python3 ptp_monitor.py --mode collector                  # https://<host>:8443 - no root needed
python3 ptp_monitor.py --mode collector --cert fullchain.pem --key privkey.pem   # your own certificate
```

- **Certificate.** With `--cert` and `--key` (PEM) the collector uses your certificate. Without them it creates a **self-signed** one in the data directory on the first start (valid 825 days, for `localhost`, the host name and the host's IP; add more with `--tls-san NAME`, repeatable) and prints its SHA-256 fingerprint. Self-signed creation needs the `cryptography` package (in `requirements.txt`) or the `openssl` command. To renew a self-signed certificate, delete `collector.crt` and `collector.key` from the data directory and restart; nodes that pin the fingerprint then need the new one.
- **Data directory** (`--data-dir`, default `./ptp_collector_data`, or `$PTP_DATA_DIR`) holds `users.json`, `nodes.json` and the generated certificate and key, all mode `0600`. It contains secrets: back it up, don't commit it. Passwords are stored as scrypt hashes and node tokens as SHA-256 hashes. Everything else (the nodes' data) stays in memory, as in standalone mode.
- **First start.** The collector creates the user `admin`. If you set `PTP_ADMIN_PASSWORD` (or `--admin-password`) that is its password; otherwise a random one is printed **once** and you must change it at the first login.
- **Port and address.** Defaults: `0.0.0.0:8443`, never moved to another port (nodes need a fixed one). Change with `--host` / `--port`.

### Users

Log in at `https://<collector>:8443`. Two roles: **viewer** (sees every node) and **admin** (also manages nodes and users on the **Admin** page). Admins add users (the new user must choose their own password at the first login), reset passwords, change roles and delete users. Everyone can change their own password on the **Account** page (at least 10 characters).

From the command line (works while the collector runs; it notices within a second):

```bash
python3 ptp_monitor.py --mode collector --add-user alice --role viewer     # asks for the password
python3 ptp_monitor.py --mode collector --set-password alice
# non-interactive: PTP_NEW_PASSWORD=... python3 ptp_monitor.py --mode collector --add-user alice
```

Logins last 12 hours of inactivity (`--session-hours`). Repeated failed logins are throttled per address and per user name (HTTP 429).

### Add a node

1. On the collector's **Admin** page, enter a node name and press **Add node**. The **token** is shown once. (Command line: `--mode collector --add-node NAME`; replace a lost or leaked token with **New token** or `--rotate-node NAME`. The old token stops working immediately.)
2. On the node (Linux/macOS/Windows with scapy, as root/Administrator), save the token to a file and start it:

```bash
echo 'ptpn_…' > node.token && chmod 600 node.token
sudo python3 ptp_monitor.py --mode node -i eth1 \
     --collector-url https://collector.example.com:8443 \
     --token-file node.token \
     --collector-fingerprint AA:BB:CC:…      # self-signed collector certificate
```

The node connects **outbound** only (it works behind NAT and firewalls, and needs no open port), sends its dashboard data every 2 seconds over a kept-alive HTTPS connection, and retries by itself if the collector is unreachable. It also accepts `--join-domain`, `--ttl`, `--bpf`, `--buffer-mb` and the other capture options.

**How a node trusts the collector** (pick one):

| Collector certificate | Node option |
|---|---|
| Publicly trusted (for example Let's Encrypt) | none, the system trust store is used |
| Signed by your own CA | `--collector-ca ca.pem` |
| Self-signed (the default) | `--collector-fingerprint AA:BB:…` (printed at collector start-up and on the Admin page) |
| (testing only) | `--insecure-skip-verify` |

The node refuses `http://` URLs, so its token is never sent unencrypted. The token can also be given in the `PTP_NODE_TOKEN` environment variable, which keeps it out of the process list (`--token TOKEN` exists but is visible there).

### Joining a PTP domain from the collector

On a node's dashboard, admins get the same "Participate in a PTP domain" form as in standalone mode (domain, interface, Delay_Req rate, multicast/unicast, TTL, timescale, pinned master). **Join domain** makes the *node* a slave-only ordinary clock in that domain, and the node's measurement shows up on the collector's page exactly as it does standalone: the time the grandmaster gives, the correction and path-delay charts with the mean ± 2σ band, and the statistics table. **Leave** ends it. Viewers see the measurement but not the form.

- The interface list is the interfaces the node is **already capturing on** (the slave needs the capture's packet timestamps), so start the node with `-i` for that interface.
- A command waits on the collector until the node's next push, which is how it reaches a node that only connects out. Expect the node to join within about one push interval (2 s by default); the page says "sent to the node, waiting" and then shows the result or the error the node reported.
- Only two commands exist (join and leave), both checked again on the node. A node can refuse them altogether with `--no-remote-control` (`PTP_NO_REMOTE_CONTROL=1`); the form then reports that remote control is switched off. Joining makes the node send Delay_Req packets, so enable it only where that is acceptable.
- Measurement only: the node's clock is never adjusted, as in standalone mode. A node that restarts is no longer in the domain; give it `--join-domain N` if it should join at every start.
- The commands and their outcomes are logged on the collector (who told which node to do what) and on the node.

### Reading the collector

- **Nodes** page: one row per node with status (online, offline, capture stopped, never connected), when data last arrived, the interfaces it captures on, the grandmaster per domain, hosts sending Sync and the message rate, plus totals over all online nodes.
- Click a node for its **full dashboard**. If a node stops reporting, the page keeps showing its last known state with an "offline" banner. A node is offline after missing about three pushes (at least 10 s).
- The Delay_Req **CSV** download works per node. The `.pcap` download and the capture controls (start, stop, clear, buffer size, IGMP re-join) are **not** available on the collector, because the raw packets stay on the node. For a `.pcap`, open the node's own standalone dashboard or capture on the node.
- The packet list shows the most recent 200 packets of the node, filtered on the collector.

### Containers

The same image runs all three modes (`PTP_MODE=standalone|node|collector`); see [Running in a container](#running-in-a-container) and the compose files `docker-compose.collector.yml` (port 8443, a `/data` volume, no special privileges) and `docker-compose.node.yml` (host networking, `NET_RAW` + `NET_ADMIN`, no published port).

| Variable | Mode | Meaning |
|---|---|---|
| `PTP_MODE` | all | `standalone` (default), `node` or `collector` |
| `PTP_COLLECTOR_URL` | node | `https://collector:8443` |
| `PTP_NODE_TOKEN` or `PTP_NODE_TOKEN_FILE` | node | the node's token (or a path to a file holding it, such as a Docker secret) |
| `PTP_COLLECTOR_FINGERPRINT` / `PTP_COLLECTOR_CA` | node | how to trust the collector's certificate (see above) |
| `PTP_INTERFACES` | node | interfaces to capture on, e.g. `eth1` (**required**) |
| `PTP_PUSH_INTERVAL` | node | seconds between pushes (default 2) |
| `PTP_NO_REMOTE_CONTROL` | node | `1` = the collector may not make this node join a PTP domain |
| `PTP_HOST` / `PTP_PORT` | collector | bind address and HTTPS port (default `0.0.0.0:8443`) |
| `PTP_DATA_DIR` | collector | accounts, tokens and generated certificate (default `/data`; keep it on a volume) |
| `PTP_CERT` / `PTP_KEY` | collector | your own certificate and key (PEM, paths inside the container) |
| `PTP_TLS_SAN` | collector | extra names/IPs for the self-signed certificate, comma separated |
| `PTP_ADMIN_PASSWORD` | collector | password of the first `admin` account (else random, printed once in the log) |
| `PTP_SESSION_HOURS` | collector | idle time before a login expires (default 12) |

The health check follows the mode: the collector answers `/healthz`; a node is healthy while the collector keeps accepting its pushes.

### Security of the collector

- HTTPS only (TLS 1.2 or newer). There is no plain-HTTP listener. The session cookie is `Secure`, `HttpOnly` and `SameSite=Strict`, and the pages are sent with HSTS, a Content-Security-Policy and `X-Frame-Options: DENY`.
- Sessions are server side: logging out, deleting a user or changing a password ends them at once. POST requests must be JSON from the same origin, which stops other sites from acting on a logged-in browser.
- A node's name comes from its token, not from what the node says, so one node cannot pose as another. A node can only push data (and receive the join/leave commands an admin sends it); it cannot read anything or log in. Only admins can send those commands, and a node can switch them off with `--no-remote-control`. Treat a node token like a password: whoever has it can send data under that node's name (use **New token** if one leaks). The collector shows what nodes send like any dashboard data, so only register nodes you trust.
- The collector has no capture endpoints (its only control is the admin-only join/leave command for nodes) and does not need root: run it as an unprivileged user (port 8443 is above 1024).
- The first-start password, `--admin-password` and `--token` are visible in the process list or logs; prefer the environment variables, a token file and changing the first password at once.
- Limits: pushes over 8 MB (compressed) or 64 MB (decompressed) are refused.

---

## Command-line options

| Option | Default | Description |
|---|---|---|
| `--mode MODE` | `standalone` | `standalone`, `node` or `collector` (see [Collector and nodes](#collector-and-nodes)). Also `PTP_MODE`. |
| `--host ADDR` | `127.0.0.1` (collector: `0.0.0.0`) | Address the web UI listens on. Use `0.0.0.0` to reach a standalone UI from other machines (see [Security notes](#security-notes)). |
| `--port N` | `8080` (collector: `8443`) | Web UI port. If you don't give `--port` and 8080 is busy, the next free port (up to 8129) is used. A port you give explicitly is never changed, and the collector never moves. |
| `-i IFACE`, `--interface IFACE` | – | Start capturing on this interface immediately. Repeatable. |
| `--bpf FILTER` | `(udp and (port 319 or port 320)) or ether proto 0x88f7 or (ip proto 2)` | Capture filter (BPF syntax). `ip proto 2` is IGMP, needed for the multicast membership check. |
| `--no-promisc` | off | Do not put the interface into promiscuous mode. |
| `--buffer-mb MB` | `128` | Capture buffer size: memory for stored packets (raw frames for the .pcap plus the packet list). The oldest packets roll over when it is full. It can also be changed in the page. `--max-pcap-mb` is accepted as an alias. |
| `--join-domain N` | – | Also join PTP domain N as a slave, using the first `-i` interface. |
| `--ttl N` | `1` | IP TTL (1–255) of the Delay_Req packets sent when joining a domain. |
| `--no-igmp-keepalive` | off | Do not re-send the IGMP joins when no IGMP querier is seen. It can also be switched off in the page. |
| `--no-browser` | off | Do not open the dashboard in a browser on start-up. |

**Node mode** (`--mode node`; the capture options above apply, `-i` is required):

| Option | Default | Description |
|---|---|---|
| `--collector-url URL` | – | `https://host:8443` of the collector (required; `http://` is refused). |
| `--token-file FILE` | – | File holding the node's token. `PTP_NODE_TOKEN` in the environment works too. |
| `--token TOKEN` | – | The token on the command line (visible in the process list; prefer the file). |
| `--collector-fingerprint SHA256` | – | Trust only the collector certificate with this fingerprint (self-signed certificates). |
| `--collector-ca FILE` | – | CA certificate (PEM) that signed the collector's certificate. |
| `--insecure-skip-verify` | off | Do not verify the collector's certificate (testing only). |
| `--push-interval SEC` | `2` | Seconds between pushes. |
| `--no-remote-control` | off | Do not let the collector make this node join or leave a PTP domain (also `PTP_NO_REMOTE_CONTROL=1`). |

**Collector mode** (`--mode collector`; no capture options apply):

| Option | Default | Description |
|---|---|---|
| `--cert FILE`, `--key FILE` | self-signed | TLS certificate (PEM, may include the chain) and private key. Give both or neither. |
| `--tls-san NAME` | – | Extra DNS name or IP for the self-signed certificate. Repeatable. |
| `--data-dir DIR` | `./ptp_collector_data` | Accounts, node tokens, generated certificate. Also `PTP_DATA_DIR`. |
| `--session-hours H` | `12` | Idle time before a login expires. |
| `--admin-password PW` | random, printed once | Password of the first `admin` account (prefer `PTP_ADMIN_PASSWORD`). |
| `--add-user NAME` `[--role admin\|viewer]` | – | Create a user and exit. The password is asked for, or taken from `PTP_NEW_PASSWORD`. |
| `--set-password NAME` | – | Change a user's password and exit. |
| `--add-node NAME` / `--rotate-node NAME` | – | Register a node, or replace its token, print the token and exit. |

---

## The dashboard, section by section

### Overview boxes
PTP messages captured, messages/s (5 s average), total throughput received (frame bytes), current bandwidth (5 s average), hosts sending Sync, and capture time.

### 1. Choose interface(s) to enable
- The **IPv4 address** is shown in green, the **MAC** in purple, and "no IPv4 address" in red. An interface without an IPv4 address can't join the multicast groups.
- **Start capture / Stop / Clear data / Download .pcap / Refresh interfaces**.
- **Capture buffer** size and its usage (see [Capture buffer](#capture-buffer)).
- **Multicast membership (IGMP)** panel, shown while capturing. One row per interface:
  - **Joined (per the OS)**: ✓ / ✗ for each PTP group, read from the operating system's own membership table (`/proc/net/igmp` on Linux, `netstat -g` on macOS, `netsh interface ipv4 show joins` on Windows).
  - **Join report seen on the wire**: this computer's own IGMP join reports, captured as they leave the interface. This proves the join went out of *this* interface.
  - **IGMP querier on the network**: the router or switch sending IGMP queries, with its IGMP version and the time of its last query.
  - **OS IGMP version**, **PTP packets** received on the interface, and **Re-joins** done.
  - **Re-join groups now** leaves and joins the groups again, which makes the computer send fresh join reports.
  - **Keep joins alive when no IGMP querier is seen** re-joins every 60 s once no query has been seen for 130 s.
  - Hints below the table explain what is wrong, for example no querier, a join missing from the OS table, or joined but no PTP arriving.

### Charts
- Messages received per second (last 5 min).
- Total by message type.
- Per-second rate by message type: click a legend entry to turn that type on or off.
- One small chart per message type, with total, messages/s now, and per-second min, max and average.

### Hosts sending Sync
One row per (host, clock identity, domain), grouped under a collapsible **Domain N** header. The header shows the number of hosts, how many are boundary clocks, the total Sync rate and the grandmaster.

- **Role**: Grandmaster, Boundary clock (with "under *x*", the clock it follows) or Master. The role comes from the clock hierarchy.
- Boundary clocks are **indented under their grandmaster**. A ▾ next to a grandmaster (or a boundary clock with others below it) collapses everything under it.
- **Announced interval** (`logMessageInterval` of the Sync) next to the **Observed interval** (measured). The observed value turns orange when it differs from the announced one by more than 25 %.
- **Sync/s (from interval)**, **Sync/s (measured)**, **Sync packets**, **Total msgs/s (measured)** (all PTP messages from that host), **All PTP packets** and **Last seen**.

### Announce messages – clocks ranked by the Best Master Clock Algorithm
Every clock sending Announce, grouped by domain. Clocks are ranked with the IEEE 1588 data-set comparison in this order: priority1 → clock class → clock accuracy → offset-scaled log variance → priority2 → grandmaster identity. For the same grandmaster, the tie-breakers are steps removed and then sender identity.

- **Rank 1 is the current grandmaster**, and the rows below it are its successors. The last column says why each clock ranks below the one above it.
- **Boundary clocks are left out of the ranking.** A boundary clock is a sender whose own clock identity differs from the grandmaster identity it announces (steps removed > 0). It only relays the true grandmaster's data set, so it is never a grandmaster candidate. Tick **Show boundary clocks (not ranked)** to list them, greyed out. If a domain has *only* boundary clocks on this segment, its header says the grandmaster is not on this segment.
- A clock is **expired** after 3 announce intervals without an Announce. A clock is **not eligible** if it sets the alternate-master flag or has clock class 255.
- The table also shows the clock class and accuracy (decoded), time source, UTC offset and flags (as chips with tooltips), the announce interval, and the number of Announces seen.
- An event log below the table records grandmaster changes.

### 2. Participate in a PTP domain (optional)
The program acts as a **slave-only ordinary clock**. It picks the best master in the domain from the Announce messages and sends Delay_Req after its Sync / Follow_Up. Then it computes, for every exchange:

```
offset     = ((t2 − t1) − (t4 − t3)) / 2      (this host minus master)
path delay = ((t2 − t1) + (t4 − t3)) / 2
correction = −offset
```

The correction fields of Sync, Follow_Up and Delay_Resp are applied. For a master on the PTP timescale, its TAI timestamps are converted to UTC using `currentUtcOffset`, unless you choose "PTP / TAI" as the local timescale.

| Setting | Choices |
|---|---|
| Domain number | 0 – 127 |
| Interface | any interface that is capturing |
| Delay_Req rate | Auto (the master's `logMinDelayReqInterval` from Delay_Resp), every Sync, or fixed 16/s … 1 per 4 s |
| Send Delay_Req | Multicast (domains 0–3 → 224.0.1.129–.132, other domains → 224.0.1.129) or unicast to the master |
| TTL | 1 – 255 (the IP maximum; 1 keeps packets on the local subnet) |
| Local clock timescale | UTC (convert master TAI) or PTP/TAI (no conversion) |
| Only follow master IP | optional, pin a specific master |

What it shows:
- **Time given by the grandmaster** in **UTC** and **TAI** (nanosecond resolution). This is the last Sync origin timestamp carried forward by the local clock. UTC = TAI − `currentUtcOffset` from the Announce.
- Boxes: master, latest correction, latest path delay, number of measurements, Delay_Req sent / Delay_Resp received, Sync count.
- **Clock correction per measurement** chart, with a dashed mean ± 2σ band and outliers in red, and a **Mean path delay** chart.
- **Statistics** table for correction and path delay: Max, Min, Average, Median, standard deviation (1σ), 2nd standard deviation (2σ), count and % outside mean ± 2σ, and total measurements.

Our own clock identity is built from the interface MAC (EUI-64), with port number `0x7001`. Timestamps are the capture timestamps of the packets, so accuracy is that of software timestamping (see [Limitations](#limitations)). **The host clock is never adjusted.**

### Captured packets (newest first)
Shows the last 200 matching packets. You can filter by message type and by text (IP, clock identity, interface or type), and **Pause list** freezes it. Columns: #, time, interface, source, destination, transport, **DSCP** (value and name, `-` for Layer-2 PTP), type, domain, sequence ID, log interval and length.

### Delay_Req interval check
This section finds hosts sending Delay_Req at a different interval than the Sync interval of their **domain grandmaster** (the best Announce clock).

- The real interval is **measured** from arrival times, as the median of the last 128 gaps. At least 10 gaps are needed before a host is judged.
- A host is flagged as **Mismatch** when its interval is more than about 30 % faster or slower than the grandmaster's Sync interval.
- **A header value of 127 (0x7F) is never treated as a mismatch.** IEEE 1588 fixes the Delay_Req `logMessageInterval` field at 0x7F; the real rate is set by the master's `logMinDelayReqInterval` in Delay_Resp. Only a header value *other than* 127 that differs from the Sync interval is reported.
- The **GM-requested interval (Delay_Resp)** column is shown for context. If a host differs from Sync but matches what the grandmaster asks for, the row says so, because that behaviour is allowed by the standard.
- By default only mismatches are listed. Tick the checkbox to also see matching, idle and still-measuring hosts. **Download CSV** saves the table as shown.

### Clock hierarchy – who is clocking off whom, per domain
Every PTP device seen, grouped by domain and drawn as a tree under the clock it follows. Columns: device, clock identity, role, the IP and clock identity it is clocking off, how that was determined, grandmaster, steps removed, number of followers, message types it sends, and last seen. Roles are Grandmaster, Boundary clock, Master and Slave.

How each link is found, most reliable first:
1. **Delay_Resp**: a master's Delay_Resp names the port it is answering (`requestingPortIdentity`), so that device is clocking off the master.
2. **Announce**: a sender announcing *itself* as grandmaster is the root. A boundary clock is placed under the only clock announcing the same grandmaster one step closer.
3. **Unicast Delay_Req**: the destination is the device's master.
4. Otherwise the device is assumed to follow the domain's current best master. These rows are marked *inferred* in orange.

A ▾ next to a grandmaster or boundary clock collapses everything under it. If this program has joined a domain, it appears in the tree as "(this monitor)".

**Search.** Type in the search box above the table to find devices by any part of their **IP address**, **clock identity** or **MAC address**.
- Separators don't matter for clock identities and MACs, so `00-1B-19-00-00-20`, `001b.1900.0020` and `00:1b:19:00:00:20` all find the same device.
- IP text such as `10.0` is matched only against IP addresses.
- Matching devices are highlighted, and the clocks above each match (its path to the grandmaster) are kept for context.
- Domains without a match are hidden, and collapsed domains or subtrees open while searching.
- **Esc** clears the search.

### MAC addresses
IEEE 1588 builds a clock identity from a 48-bit MAC address by putting `FF:FE` in the middle: `aa:bb:cc:FF:FE:dd:ee:ff` comes from MAC `aa:bb:cc:dd:ee:ff`. No bits are flipped, unlike IPv6 addresses. Whenever a clock identity has that form, its MAC is shown:
- in its own column in the Clock hierarchy
- under the clock identity in Hosts sending Sync, the Announce table (sender and grandmaster) and the Delay_Req check
- as a column in the Delay_Req CSV

A clock identity in any other form (a native EUI-64 or a vendor scheme) contains no MAC address, so "MAC –" is shown instead.

### Theme
The **System / Light / Dark** switch at the top right sets the colour theme. **System** (the default) follows the computer's light or dark setting and changes with it. The choice is remembered in the browser, and charts redraw in the new colours straight away.

### Collapsing
Every domain header in Hosts sending Sync, Announce and Clock hierarchy can be clicked to collapse it. Each section also has **Expand all / Collapse all**. The state is remembered in your browser.

---

## Exports

| Export | Where | Format |
|---|---|---|
| **Download .pcap** | Section 1 | Classic libpcap, Ethernet link type, microsecond timestamps. Opens in Wireshark, tcpdump and tshark. File name `ptp_capture_YYYYMMDD_HHMMSS.pcap`. |
| **Download CSV** | Delay_Req interval check | UTF-8 CSV with BOM (opens correctly in Excel). Intervals are given as log2 and in seconds, times in UTC. File name `ptp_delay_req_check_YYYYMMDD_HHMMSS.csv`. |

About the .pcap:
- It contains every frame the capture filter let through, including IGMP (queries and this computer's join reports) and the Delay_Req packets this program sends when it has joined a domain.
- Loopback frames (macOS `lo0`) get a synthetic Ethernet header, so the whole file uses one link type.
- Frames from other link types are skipped and counted under the button.

---

## Capture buffer

One memory limit covers everything stored per packet: the raw frames for the .pcap download and the decoded rows for the packet list.

- Set it in the page (**Capture buffer … MB → Apply**) or with `--buffer-mb`. It can be changed while capturing; shrinking it drops the oldest data immediately.
- The default is **128 MB**. Allowed values are 1 MB up to 75 % of the computer's physical memory.
- When the buffer is full, the **oldest packets roll over** to make room for new ones, so you always keep the most recent capture. The status line shows usage, when the oldest kept packet arrived, and how many packets have rolled over. It turns orange when the buffer is full.
- The packet-list share is an estimate (about 700 bytes per decoded packet), so real memory use can differ a little from the setting.
- Summaries do not count toward the buffer: counters, charts, and the host, clock and hierarchy tables. They are small and keep covering the whole capture. The per-second chart history is kept for one hour.
- **Clear data** empties the buffer and resets all statistics.

---

## HTTP API

This is the API of a **standalone** program. (The collector serves the same `/api/state`, `/api/packets` and `/api/dreq.csv` read-only for each node with a `?node=NAME` parameter, behind the login. Its only control endpoints are the admin-only `POST /api/slave/start` and `/api/slave/stop` (`?node=NAME`), which queue a join/leave for the node.)

The page is driven by a small JSON API, which you can also use from scripts. POST requests must send `Content-Type: application/json`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | The dashboard |
| GET | `/api/interfaces[?all=1]` | Interfaces (active wired only, or all with `all=1`) |
| GET | `/api/state` | Everything the dashboard shows (stats, hosts, Announce ranking, hierarchy, Delay_Req check, slave, buffer, multicast membership) |
| GET | `/api/packets?limit=200&type=Sync&q=text` | Recent packets (limit up to 1000) |
| GET | `/api/pcap` | Download the capture as .pcap |
| GET | `/api/dreq.csv[?all=1]` | Download the Delay_Req check (mismatches only, or all with `all=1`) |
| POST | `/api/start` `{"interfaces": ["eth1"]}` | Start capturing |
| POST | `/api/stop` | Stop capturing (also leaves a joined domain) |
| POST | `/api/clear` | Clear all data |
| POST | `/api/buffer` `{"mb": 256}` | Set the capture buffer size |
| POST | `/api/rejoin` | Leave and re-join the PTP groups on all capture interfaces |
| POST | `/api/igmp_keepalive` `{"on": true}` | Turn the join keep-alive on or off |
| POST | `/api/slave/start` `{"domain":0,"iface":"eth1","dreq":"auto","unicast":false,"ttl":1,"timescale":"utc","force_master":""}` | Join a domain |
| POST | `/api/slave/stop` | Leave the domain |

Example:

```bash
curl -s http://127.0.0.1:8080/api/state | python3 -m json.tool | less
curl -s -X POST -H 'Content-Type: application/json' -d '{"mb":512}' http://127.0.0.1:8080/api/buffer
curl -s -o capture.pcap http://127.0.0.1:8080/api/pcap
```

---

## Security notes

- By default the UI listens on **127.0.0.1 only**.
- `--host 0.0.0.0` makes it reachable from the network **without any authentication**. Anyone who can reach the port can start or stop captures, download the capture, and make the host send PTP packets. Only do this on a trusted network.
- POST requests must be JSON, which stops other web pages in your browser from submitting forms to the API.
- The program runs as root because packet capture needs it. Under `sudo`, the browser is started as your normal user.
- Need access from several machines or users? Use a collector (HTTPS, login) rather than `--host 0.0.0.0`: see [Security of the collector](#security-of-the-collector).

---

## Limitations

- **Software timestamps.** Correction and path-delay figures come from the capture timestamps, not PTP hardware timestamping. Expect tens of microseconds of noise. Use them for trends, comparisons and spotting problems, not as a reference measurement.
- **Measurement only.** Joining a domain never disciplines the local clock.
- **End-to-end delay only.** Peer-to-peer (Pdelay) messages are captured and counted, but are not used for measurements or for the hierarchy.
- **IPv4 multicast join.** The IGMP join covers the IPv4 groups. IPv6 PTP (FF0x::181) and Layer-2 PTP are captured only if they reach the interface anyway, for example in promiscuous mode or on a span port.
- **Visibility.** The hierarchy and Delay_Req check only see traffic that reaches the chosen interface(s). Masters on other segments appear as "upstream not visible", and switches with IGMP snooping may hide some traffic.
- **Memory.** All data lives in memory; nothing is written to disk unless you download it. (The collector also keeps its accounts and node tokens on disk, and the latest data of each node in memory only, so a collector restart shows nodes empty until their next push.)
- **Collector view.** It shows each node's latest state, not a history; it has no `.pcap` download and no capture controls (apart from joining/leaving a PTP domain) (see [Reading the collector](#reading-the-collector)). Node data crosses the network only as the dashboard summary plus the latest 200 packets. The node's clock and the collector's clock are not compared: times in tables are the node's.

---

## Troubleshooting

| Problem | What to do |
|---|---|
| Container shows no interfaces / no packets | Use `--network host` (`network_mode: host`) and add `NET_RAW` + `NET_ADMIN`. On macOS / Windows Docker Desktop the container can't reach the computer's own Ethernet ports, so run the script directly there. |
| Node: `Cannot send to the collector (… CERTIFICATE_VERIFY_FAILED …)` | The collector's certificate is not trusted. For a self-signed one, give the node `--collector-fingerprint` (shown at collector start-up and on the Admin page); for your own CA use `--collector-ca`. Also check that the URL's host name is in the certificate (`--tls-san` when the collector creates it). |
| Node: `the collector refused this node's token (HTTP 401)` | The token is wrong, was replaced (**New token**) or the node was removed. Copy the current token from the Admin page. |
| Collector: joining a domain says "failed" or "did not confirm" | The message is the node's own answer, for example "Start the capture on eth1 first" or "eth1 has no IPv4 address, cannot send Delay_Req". "The node is offline" means it has stopped pushing. "Remote control is switched off" means the node runs with `--no-remote-control`. |
| Node: `Connection refused` / timeout | The collector is not running, the URL or port is wrong, or a firewall blocks outbound 8443. The node retries by itself. |
| Node shows "never connected" or "offline" on the collector | Check the node's console output. A node without a working capture (not root, wrong interface name) still connects but shows "capture stopped". |
| Forgot the collector's admin password | On the collector host: `python3 ptp_monitor.py --mode collector --data-dir DIR --set-password admin`. |
| Browser warns about the collector's certificate | Expected with the self-signed default. Use `--cert`/`--key` with a certificate your browsers trust, or accept the warning once after checking the fingerprint. |
| `This program needs scapy` | Install the requirements for the interpreter you run with `sudo` (see [Installation](#installation)). |
| `Address already in use` / port busy | Without `--port`, the next free port is used automatically. With an explicit `--port`, pick another one, or find the process: `sudo lsof -nP -iTCP:8080 -sTCP:LISTEN` (often an earlier copy still running). |
| Browser doesn't open | Open the URL printed in the terminal. Use `--no-browser` on headless systems. |
| Interface missing from the list | It may be Wi-Fi, VPN/tunnel, loopback or link-down. Tick **Show all interfaces (advanced)** and press **Refresh interfaces**. |
| "no IPv4 address" | The multicast join needs an IPv4 address on that interface. Configure one, or capture on a span port. |
| No packets | Look at the **Multicast membership (IGMP)** panel in section 1 and follow its hints. In short: ✓ in "Joined (per the OS)" plus a join report "seen on the wire" means this computer did its part. If no IGMP querier is seen, enable one on the switch for the PTP VLAN, or turn IGMP snooping off there; without a querier, snooping switches often never forward the PTP groups. If a querier is present and joins look fine, check that the port is in the PTP VLAN and that a grandmaster is running. Also check that you are root/Administrator (Npcap on Windows) and that the right interface is ticked. |
| Join domain says "start the capture first" | Start capturing on the same interface in section 1, then join. |
| Corrections are noisy | Expected with software timestamps (see [Limitations](#limitations)). Compare the 2σ value over time rather than single samples. |
