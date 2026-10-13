# PTP Monitor (`ptp_monitor.py`)

A single-file Python tool for watching IEEE 1588 Precision Time Protocol (PTP) traffic on a network. Pick one or more wired interfaces and it joins the PTP multicast groups and captures every PTP packet. It then shows everything live in a browser dashboard: message rates, the hosts sending Sync, the clocks ranked by the Best Master Clock Algorithm, who is clocking off whom, and Delay_Req behaviour.

It can also join a PTP domain as a measurement-only slave and chart the clock corrections it would apply. The capture can be downloaded as a `.pcap` for Wireshark at any time.

- One Python file, one dependency (scapy).
- Runs on Linux, macOS and Windows.
- The web UI is served by the program itself and opens in your browser automatically.
- It only listens and measures. It never changes this computer's clock.

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
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

## Command-line options

| Option | Default | Description |
|---|---|---|
| `--host ADDR` | `127.0.0.1` | Address the web UI listens on. Use `0.0.0.0` to reach it from other machines (see [Security notes](#security-notes)). |
| `--port N` | `8080` | Web UI port. If you don't give `--port` and 8080 is busy, the next free port (up to 8129) is used. A port you give explicitly is never changed. |
| `-i IFACE`, `--interface IFACE` | – | Start capturing on this interface immediately. Repeatable. |
| `--bpf FILTER` | `(udp and (port 319 or port 320)) or ether proto 0x88f7 or (ip proto 2)` | Capture filter (BPF syntax). `ip proto 2` is IGMP, needed for the multicast membership check. |
| `--no-promisc` | off | Do not put the interface into promiscuous mode. |
| `--buffer-mb MB` | `128` | Capture buffer size: memory for stored packets (raw frames for the .pcap plus the packet list). The oldest packets roll over when it is full. It can also be changed in the page. `--max-pcap-mb` is accepted as an alias. |
| `--join-domain N` | – | Also join PTP domain N as a slave, using the first `-i` interface. |
| `--ttl N` | `1` | IP TTL (1–255) of the Delay_Req packets sent when joining a domain. |
| `--no-igmp-keepalive` | off | Do not re-send the IGMP joins when no IGMP querier is seen. It can also be switched off in the page. |
| `--no-browser` | off | Do not open the dashboard in a browser on start-up. |

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

---

## Limitations

- **Software timestamps.** Correction and path-delay figures come from the capture timestamps, not PTP hardware timestamping. Expect tens of microseconds of noise. Use them for trends, comparisons and spotting problems, not as a reference measurement.
- **Measurement only.** Joining a domain never disciplines the local clock.
- **End-to-end delay only.** Peer-to-peer (Pdelay) messages are captured and counted, but are not used for measurements or for the hierarchy.
- **IPv4 multicast join.** The IGMP join covers the IPv4 groups. IPv6 PTP (FF0x::181) and Layer-2 PTP are captured only if they reach the interface anyway, for example in promiscuous mode or on a span port.
- **Visibility.** The hierarchy and Delay_Req check only see traffic that reaches the chosen interface(s). Masters on other segments appear as "upstream not visible", and switches with IGMP snooping may hide some traffic.
- **Memory.** All data lives in memory; nothing is written to disk unless you download it.

---

## Troubleshooting

| Problem | What to do |
|---|---|
| `This program needs scapy` | Install the requirements for the interpreter you run with `sudo` (see [Installation](#installation)). |
| `Address already in use` / port busy | Without `--port`, the next free port is used automatically. With an explicit `--port`, pick another one, or find the process: `sudo lsof -nP -iTCP:8080 -sTCP:LISTEN` (often an earlier copy still running). |
| Browser doesn't open | Open the URL printed in the terminal. Use `--no-browser` on headless systems. |
| Interface missing from the list | It may be Wi-Fi, VPN/tunnel, loopback or link-down. Tick **Show all interfaces (advanced)** and press **Refresh interfaces**. |
| "no IPv4 address" | The multicast join needs an IPv4 address on that interface. Configure one, or capture on a span port. |
| No packets | Look at the **Multicast membership (IGMP)** panel in section 1 and follow its hints. In short: ✓ in "Joined (per the OS)" plus a join report "seen on the wire" means this computer did its part. If no IGMP querier is seen, enable one on the switch for the PTP VLAN, or turn IGMP snooping off there; without a querier, snooping switches often never forward the PTP groups. If a querier is present and joins look fine, check that the port is in the PTP VLAN and that a grandmaster is running. Also check that you are root/Administrator (Npcap on Windows) and that the right interface is ticked. |
| Join domain says "start the capture first" | Start capturing on the same interface in section 1, then join. |
| Corrections are noisy | Expected with software timestamps (see [Limitations](#limitations)). Compare the 2σ value over time rather than single samples. |
