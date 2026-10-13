#!/usr/bin/env python3
"""
PTP Multicast Monitor
=====================

Pick one or more wired network interfaces, join the PTP multicast groups
224.0.1.129 - 224.0.1.132 on them (IGMP), capture every PTP packet that arrives
(UDP 319/320 and Layer-2 PTP, EtherType 0x88F7) and watch it live in a browser
dashboard that opens automatically:

  * overview: messages captured, messages/s, throughput, bandwidth
  * charts per second, per message type (clickable legend) and per-type cards
    with total, messages/s, min, max and average
  * hosts sending Sync, grouped by domain, with boundary clocks shown under
    their grandmaster (collapsible)
  * clocks sending Announce ranked per domain with the IEEE 1588 best master
    clock algorithm (boundary clocks are not grandmaster candidates)
  * clock hierarchy: which device is clocking off which clock, per domain
  * Delay_Req interval check against the grandmaster's Sync interval (CSV)
  * captured packet list with DSCP, .pcap download, rolling capture buffer
  * multicast membership check: OS join table, this host's IGMP join reports,
    the network's IGMP querier, and a join keep-alive when there is no querier
  * MAC address derived from each clock identity, a searchable clock hierarchy
    (IP, clock identity or MAC), and a System / Light / Dark theme switch

Optional: join a PTP domain as a slave-only ordinary clock.  The program
follows the best master, sends Delay_Req messages, computes offset and path
delay (end-to-end mechanism), charts the corrections with Max / Min / Average /
Median / 2-sigma statistics and shows the grandmaster's time in UTC and TAI.
It measures only - it never adjusts this host's clock.

Requirements
------------
  Python 3.8+,  pip install -r requirements.txt   (scapy; psutil optional)
  Linux/macOS: run as root (raw capture + IGMP join).
  Windows: install Npcap and run from an elevated prompt.

Usage  (see README.md for everything else)
-----
  sudo python3 ptp_monitor.py                  # opens http://127.0.0.1:8080
  sudo python3 ptp_monitor.py --port 9000 --no-browser
  sudo python3 ptp_monitor.py -i eth1 -i eth2  # start capturing right away
  sudo python3 ptp_monitor.py -i eth1 --join-domain 0 --ttl 16
  sudo python3 ptp_monitor.py --buffer-mb 512  # bigger capture buffer
"""
import argparse
import csv
import io
import errno
import json
import math
import os
import re
import shutil
import socket
import datetime
import struct
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    from scapy.all import (AsyncSniffer, Dot1Q, Ether, IP, IPv6, UDP, conf,
                           get_if_addr, get_if_hwaddr, get_if_list)
except ImportError:
    sys.exit("This program needs scapy:  pip install scapy")

GROUPS = ["224.0.1.129", "224.0.1.130", "224.0.1.131", "224.0.1.132"]
# IEEE 1588 Annex D: domains 0-3 have their own group, 4-127 use 224.0.1.129
DOMAIN_GROUPS = {0: GROUPS[0], 1: GROUPS[1], 2: GROUPS[2], 3: GROUPS[3]}
# PTP over UDP and Layer 2, plus IGMP (ip proto 2) so the multicast joins and
# the network's IGMP querier can be checked
DEFAULT_BPF = "(udp and (port 319 or port 320)) or ether proto 0x88f7 or (ip proto 2)"
SLAVE_PORT_NUMBER = 0x7001      # portNumber used in our sourcePortIdentity
MAX_TTL = 255                   # IPv4 TTL is an 8-bit field (PTP sets no lower cap)

TYPE_ORDER = ["Announce", "Sync", "Follow_Up", "Delay_Req", "Delay_Resp",
              "Pdelay_Req", "Pdelay_Resp", "Pdelay_Resp_Follow_Up",
              "Signaling", "Management"]
V2_TYPES = {0x0: "Sync", 0x1: "Delay_Req", 0x2: "Pdelay_Req",
            0x3: "Pdelay_Resp", 0x8: "Follow_Up", 0x9: "Delay_Resp",
            0xA: "Pdelay_Resp_Follow_Up", 0xB: "Announce",
            0xC: "Signaling", 0xD: "Management"}
V1_TYPES = {0: "Sync", 1: "Delay_Req", 2: "Follow_Up", 3: "Delay_Resp",
            4: "Management"}


# --------------------------------------------------------------------------
# Interface helpers (addresses are looked up several ways because scapy's own
# lookup returns 0.0.0.0 on some platforms / versions)
# --------------------------------------------------------------------------
def _valid_ip(a):
    try:
        socket.inet_aton(a)
    except Exception:
        return False
    return a.count(".") == 3 and a != "0.0.0.0"


def _find_dev(name):
    try:
        ifs = conf.ifaces
    except Exception:
        return None
    for fn in ("dev_from_networkname", "dev_from_name"):
        try:
            return getattr(ifs, fn)(name)
        except Exception:
            pass
    return None


def iface_ipv4s(name):
    """All IPv4 addresses configured on an interface (primary first)."""
    found = []

    def add(a):
        a = (a or "").strip()
        if _valid_ip(a) and a not in found:
            found.append(a)

    try:
        add(get_if_addr(name))
    except Exception:
        pass
    dev = _find_dev(name)
    if dev is not None:
        try:
            for a in (getattr(dev, "ips", None) or {}).get(4, []):
                add(a)
        except Exception:
            pass
        try:
            add(getattr(dev, "ip", None))
        except Exception:
            pass
    if sys.platform.startswith("linux"):
        try:
            import fcntl
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                res = fcntl.ioctl(s.fileno(), 0x8915,           # SIOCGIFADDR
                                  struct.pack("256s", name[:15].encode()))
                add(socket.inet_ntoa(res[20:24]))
            finally:
                s.close()
        except Exception:
            pass
        if shutil.which("ip"):
            try:
                out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", name],
                                     capture_output=True, text=True, timeout=2).stdout
                for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", out):
                    add(m.group(1))
            except Exception:
                pass
    elif sys.platform != "win32" and shutil.which("ifconfig"):
        try:
            out = subprocess.run(["ifconfig", name], capture_output=True,
                                 text=True, timeout=2).stdout
            for m in re.finditer(r"\binet (\d+\.\d+\.\d+\.\d+)", out):
                add(m.group(1))
        except Exception:
            pass
    try:
        import psutil
        for a in psutil.net_if_addrs().get(name, []):
            if a.family == socket.AF_INET:
                add(a.address)
    except Exception:
        pass
    found.sort(key=lambda a: a.startswith("169.254."))   # prefer non link-local
    return found


def iface_mac(name):
    try:
        m = get_if_hwaddr(name)
        if m and m != "00:00:00:00:00:00":
            return m.lower()
    except Exception:
        pass
    dev = _find_dev(name)
    try:
        m = getattr(dev, "mac", None)
        if m and m != "00:00:00:00:00:00":
            return m.lower()
    except Exception:
        pass
    try:
        with open("/sys/class/net/%s/address" % name) as f:
            return f.read().strip().lower()
    except Exception:
        return None


def iface_state(name):
    try:
        with open("/sys/class/net/%s/operstate" % name) as f:
            return f.read().strip()
    except Exception:
        return "unknown"


# ---- interface type (Wi-Fi / cellular) and link state, per platform -------
_CELL_RE = re.compile(r"cellular|mobile broadband|wwan|wireless wan|\blte\b|"
                      r"\b[345]g\b|iphone usb", re.I)
_WIFI_RE = re.compile(r"wi-?fi|wireless|wlan|802\.11|airport", re.I)
# awdl0 / llw0 = Apple Wireless Direct Link (AirDrop/AirPlay) and its low-latency
# companion, p2p0 = Wi-Fi Direct, ap1 = Wi-Fi hotspot (macOS / iOS)
_WIFI_NAME_RE = re.compile(r"^(wl|wifi|wlan|ath\d|ra\d|awdl\d*$|llw\d*$|p2p\d*$|ap\d+$)", re.I)
_CELL_NAME_RE = re.compile(r"^(ww|rmnet|ccmni|pdp)", re.I)
_LOOP_NAME_RE = re.compile(r"^lo\d*$", re.I)        # lo (Linux), lo0 (macOS / BSD)


def _is_loopback(name, label, ips):
    return bool(_LOOP_NAME_RE.match(name) or "loopback" in str(label).lower()
                or any(a.startswith("127.") for a in ips))
_TUN_RE = re.compile(r"vpn|tunnel|wireguard|openvpn|tap-windows|wintun|tailscale|"
                     r"zerotier|anyconnect|globalprotect|forticlient|\bppp|l2tp|"
                     r"pptp|sstp|teredo|isatap|6to4|ip-https", re.I)
_TUN_NAME_RE = re.compile(
    r"^(?:tun|tap|wg|ppp|vpn|zt|utun|ipsec|gre|gretap|erspan|ip6tnl|ip6gre|ipip|"
    r"vti|vxlan|geneve|ovpn|l2tp|pptp|sstp|sit|tunl|gif|stf)\d*$|"
    r"^(?:tailscale|nordlynx|proton|cscotun|wgcf)|^zt[0-9a-z]{8}$", re.I)   # zt... = ZeroTier
# sysfs DEVTYPE / ARPHRD type values used by tunnels and VPNs on Linux
_TUN_DEVTYPES = {"wireguard", "ppp", "vxlan", "gre", "gretap", "ip6gre", "ipip",
                 "sit", "geneve", "tun", "vti"}
_TUN_ARPHRD = {"768", "769", "776", "778", "823", "512", "65534"}  # IPIP,TUNNEL6,SIT,GRE,IP6GRE,PPP,NONE


def _classify(text):
    if _CELL_RE.search(text or ""):
        return "cellular"
    if _WIFI_RE.search(text or ""):
        return "wifi"
    if _TUN_RE.search(text or ""):
        return "tunnel"
    return None


def _read_text(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None


def _linux_kind_up(name, root="/sys/class/net"):
    base = os.path.join(root, name)
    m = re.search(r"^DEVTYPE=(\S+)", _read_text(base + "/uevent") or "", re.M)
    devtype = m.group(1).lower() if m else ""
    kind = None
    if devtype == "wwan":
        kind = "cellular"
    elif (devtype == "wlan" or os.path.isdir(base + "/wireless")
          or os.path.isdir(base + "/phy80211")):
        kind = "wifi"
    elif os.path.basename(os.path.realpath(base + "/device/driver")) in (
            "qmi_wwan", "cdc_mbim"):
        kind = "cellular"
    elif (devtype in _TUN_DEVTYPES or os.path.exists(base + "/tun_flags")
          or _read_text(base + "/type") in _TUN_ARPHRD):
        kind = "tunnel"
    if kind is None:
        if _CELL_NAME_RE.match(name):
            kind = "cellular"
        elif _WIFI_NAME_RE.match(name):
            kind = "wifi"
        elif _TUN_NAME_RE.match(name):
            kind = "tunnel"
    st = _read_text(base + "/operstate")
    if st == "up":
        up = True
    elif st in ("down", "lowerlayerdown", "notpresent", "dormant"):
        up = False
    else:                                   # "unknown": fall back to UP+RUNNING
        try:
            fl = int(_read_text(base + "/flags"), 16)
            up = bool(fl & 0x1) and bool(fl & 0x40)
        except Exception:
            up = None
    return kind, up


_mac_cache = (0.0, {})


def _parse_mac_ports(text):
    out, port = {}, None
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            out[line.split(":", 1)[1].strip()] = port
            port = None
    return out


def _mac_kind_up(name):
    global _mac_cache
    if time.time() - _mac_cache[0] > 30:
        try:
            ports = _parse_mac_ports(subprocess.run(
                ["networksetup", "-listallhardwareports"], capture_output=True,
                text=True, timeout=5).stdout)
        except Exception:
            ports = {}
        _mac_cache = (time.time(), ports)
    kind = _classify(_mac_cache[1].get(name, ""))
    if kind is None and _TUN_NAME_RE.match(name):      # utun*, ipsec*, ppp*, gif*...
        kind = "tunnel"
    up = None
    try:
        out = subprocess.run(["ifconfig", name], capture_output=True, text=True,
                             timeout=3).stdout
        m = re.search(r"status:\s*(\w+)", out)
        if m:
            up = m.group(1) == "active"
        else:
            fl = re.search(r"<([^>]*)>", out)
            up = bool(fl) and "UP" in fl.group(1) and "RUNNING" in fl.group(1)
    except Exception:
        pass
    return kind, up


_win_cache = (0.0, [])


def _parse_win_adapters(text):
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    return [d for d in data if isinstance(d, dict)]


def _win_kind_up(name, dev):
    global _win_cache
    if time.time() - _win_cache[0] > 15:
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-NetAdapter | Select-Object Name,InterfaceDescription,"
                 "InterfaceGuid,Status,PhysicalMediaType,ifType | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15).stdout
            _win_cache = (time.time(), _parse_win_adapters(out))
        except Exception:
            _win_cache = (time.time(), [])
    ids = {str(x) for x in (name, getattr(dev, "name", None),
                            getattr(dev, "description", None),
                            getattr(dev, "network_name", None),
                            getattr(dev, "guid", None)) if x}
    guids = {g.lower() for s in ids
             for g in re.findall(r"\{?([0-9A-Fa-f-]{36})\}?", s)}
    for a in _win_cache[1]:
        g = str(a.get("InterfaceGuid") or "").strip("{}").lower()
        if (g and g in guids) or a.get("Name") in ids or a.get("InterfaceDescription") in ids:
            media = str(a.get("PhysicalMediaType") or "").lower()
            try:
                iftype = int(a.get("ifType"))     # IANA ifType
            except (TypeError, ValueError):
                iftype = None
            if "wireless wan" in media or iftype in (243, 244):
                kind = "cellular"
            elif "802.11" in media or "wireless lan" in media or iftype == 71:
                kind = "wifi"
            elif iftype in (131, 23):             # tunnel, PPP
                kind = "tunnel"
            else:
                kind = _classify("%s %s" % (a.get("Name"), a.get("InterfaceDescription")))
            return kind, str(a.get("Status")).lower() == "up"
    return None, None


def iface_kind_up(name, dev, label):
    """-> (kind, up): kind is None / 'wifi' / 'cellular' / 'tunnel'; up is
    True / False / None (unknown)."""
    kind = up = None
    try:
        if sys.platform.startswith("linux"):
            kind, up = _linux_kind_up(name)
        elif sys.platform == "darwin":
            kind, up = _mac_kind_up(name)
        elif sys.platform == "win32":
            kind, up = _win_kind_up(name, dev)
    except Exception:
        pass
    if kind is None:                        # name-based fallback on every platform
        if _CELL_NAME_RE.match(name):
            kind = "cellular"
        elif _WIFI_NAME_RE.match(name):
            kind = "wifi"
        elif _TUN_NAME_RE.match(name):
            kind = "tunnel"
    if kind is None:
        kind = _classify(" ".join(str(x) for x in (
            label, getattr(dev, "description", None), getattr(dev, "name", None)) if x))
    return kind, up


# --------------------------------------------------------------------------
# PTP parsing
# --------------------------------------------------------------------------
def parse_ptp(p):
    """Return a dict describing a PTP message, or None if it is not PTP."""
    # PTPv1: versionPTP (uint16) == 1, message kind in the control field
    if len(p) >= 36 and p[0] == 0 and p[1] == 1:
        ctrl = p[32]
        return dict(type=V1_TYPES.get(ctrl, "v1_control_%d" % ctrl),
                    version=1,
                    domain=p[4:20].split(b"\0")[0].decode("ascii", "replace"),
                    clock=p[22:28].hex(":"),
                    port=struct.unpack("!H", p[28:30])[0],
                    seq=struct.unpack("!H", p[30:32])[0],
                    log=None, flags=0, corr=0)
    # PTPv2 (IEEE 1588-2008/2019): 34-byte common header
    if len(p) < 34 or (p[1] & 0x0F) != 2:
        return None
    mt = p[0] & 0x0F
    log = struct.unpack("b", p[33:34])[0]
    extra = {}
    if mt == 0x9 and len(p) >= 54:            # Delay_Resp: who it answers
        extra = dict(req_clock=p[44:52].hex(":"),
                     req_port=struct.unpack("!H", p[52:54])[0])
    return dict(extra, type=V2_TYPES.get(mt, "Type_0x%X" % mt),
                version=2,
                domain=str(p[4]),
                clock=p[20:28].hex(":"),
                port=struct.unpack("!H", p[28:30])[0],
                seq=struct.unpack("!H", p[30:32])[0],
                log=None if log == 127 else log,    # 0x7F = "not applicable"
                flags=(p[6] << 8) | p[7],
                corr=int.from_bytes(p[8:16], "big", signed=True))  # 2^-16 ns


def ptp_ts_ns(b):
    """10-byte PTP Timestamp (48-bit seconds, 32-bit nanoseconds) -> ns."""
    return (int.from_bytes(b[0:6], "big") * 1_000_000_000
            + int.from_bytes(b[6:10], "big"))


def ts_to_ns(t):
    try:
        return int(Decimal(str(t)) * 1_000_000_000)
    except Exception:
        return int(float(t) * 1e9)


def clock_mac(clock):
    """MAC address a clock identity was built from, or None.

    IEEE 1588 builds a clockIdentity from a 48-bit MAC (EUI-48) by putting
    FF:FE in the middle: aa:bb:cc:FF:FE:dd:ee:ff -> MAC aa:bb:cc:dd:ee:ff (no
    bits are flipped, unlike IPv6).  Identities in any other form (a native
    EUI-64, or vendor-specific) do not contain a MAC address."""
    b = str(clock or "").lower().split(":")
    if len(b) == 8 and b[3] == "ff" and b[4] == "fe":
        return ":".join(b[:3] + b[5:])
    return None


def fmt_ptp_time(ns):
    """Nanoseconds since 1970-01-01 -> 'YYYY-MM-DD HH:MM:SS.nnnnnnnnn'."""
    sec, frac = divmod(int(ns), 1_000_000_000)
    try:
        d = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=sec)
    except OverflowError:
        return "n/a"
    return "%s.%09d" % (d.strftime("%Y-%m-%d %H:%M:%S"), frac)


DREQ_STATUS = {"mismatch": "Mismatch", "ok": "Matches", "measuring": "Measuring",
               "idle": "Idle", "unknown": "No GM Sync"}


def dreq_csv(rows):
    def lg(v):
        return "" if v is None else v

    def sec(v):
        return "" if v is None else "%g" % (2.0 ** v)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Host", "Clock identity", "MAC (from clock identity)", "Domain", "Delay_Req seen",
                "Observed interval (ms)", "Delay_Req per s",
                "Header interval field (log2)", "Header interval (s)",
                "Domain GM (Sync from)", "GM chosen by", "GM Sync interval (log2)",
                "GM Sync interval (s)", "GM-requested interval (log2, Delay_Resp)",
                "GM-requested interval (s)", "Observed / Sync", "Status", "Detail",
                "Last Delay_Req (UTC)"])
    for r in rows:
        w.writerow([
            r["src"], r["clock"], r.get("mac") or "", r["domain"], r["count"],
            "" if r["observed_ms"] is None else "%.3f" % r["observed_ms"],
            "" if r["observed_rate"] is None else "%.3f" % r["observed_rate"],
            127 if r["declared"] is None else r["declared"],
            "standard (0x7F)" if r["declared"] is None else sec(r["declared"]),
            r["gm"] or "", r["gm_basis"], lg(r["sync_log"]), sec(r["sync_log"]),
            lg(r["resp_log"]), sec(r["resp_log"]),
            "" if r["ratio"] is None else "%.3f" % r["ratio"],
            DREQ_STATUS.get(r["status"], r["status"]), r["note"],
            datetime.datetime.fromtimestamp(r["last"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]])
    return out.getvalue()


def build_delay_req(domain, clock_id, port, seq, unicast):
    flags0 = 0x04 if unicast else 0x00           # unicastFlag
    return (bytes([0x01, 0x02]) + struct.pack("!H", 44)
            + bytes([domain, 0, flags0, 0]) + bytes(8) + bytes(4)
            + clock_id + struct.pack("!HH", port, seq)
            + bytes([0x01, 0x7F]) + bytes(10))


def group_for_domain(domain):
    return DOMAIN_GROUPS.get(domain, GROUPS[0])


def calc_stats(v):
    """Max / Min / mean / median / 2-sigma and outliers beyond mean +- 2 sigma."""
    n = len(v)
    if n == 0:
        return None
    mean = math.fsum(v) / n
    sd = math.sqrt(math.fsum((x - mean) ** 2 for x in v) / (n - 1)) if n > 1 else 0.0
    s = sorted(v)
    median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    thr = 2.0 * sd
    exc = sum(1 for x in v if abs(x - mean) > thr)
    return dict(n=n, max=s[-1], min=s[0], mean=mean, median=median, sd=sd,
                two_sigma=thr, band_lo=mean - thr, band_hi=mean + thr,
                exceed=exc, exceed_pct=100.0 * exc / n)


# --------------------------------------------------------------------------
# Statistics store
# --------------------------------------------------------------------------
class Stats:
    def __init__(self, max_packets=None):
        self.lock = threading.Lock()
        self.max_packets = max_packets
        self.reset()

    def reset(self):
        with self.lock:
            self.total = 0
            self.ignored = 0
            self.type_counts = Counter()
            self.buckets = {}                 # unix second -> Counter
            self.packets = deque(maxlen=self.max_packets)
            self.src_totals = Counter()
            self.src_sec = {}                 # src -> {second: packets}
            self.src_first = {}               # src -> first timestamp
            self.sync_sec = {}                # sync key -> {second: packets}
            self.sync_hosts = {}
            self.dreq_hosts = {}              # (src, clock, domain) -> Delay_Req tracking
            self.dresp_log = {}               # (domain, src) -> (logMinDelayReqInterval, ts)
            self.dresp_links = {}             # (domain, slave clock) -> master that answers it
            self.clock_seen = {}              # (domain, clock) -> {ip: last seen}
            self.total_bytes = 0              # captured frame bytes
            self.first_sec = None             # second of the first packet
            self.cur_sec = None               # second currently being counted
            self.cur_counts = Counter()       # type -> packets in cur_sec
            self.agg = {}                     # type -> per-second min/max/avg tracking

    def _finalize_second(self):
        for t, a in self.agg.items():
            if a["first"] == self.cur_sec:
                continue                  # first second of a type is usually partial
            c = self.cur_counts.get(t, 0)
            a["n"] += 1
            a["sum"] += c
            a["min"] = c if a["min"] is None else min(a["min"], c)
            a["max"] = max(a["max"], c)

    def _roll(self, sec):
        """Close the per-second counting window(s) that ended before `sec`;
        idle seconds in between count as zero for every type."""
        if self.cur_sec is None:
            self.cur_sec = sec
            return
        if sec <= self.cur_sec:
            return
        self._finalize_second()
        idle = sec - self.cur_sec - 1
        if idle > 0:
            for a in self.agg.values():
                a["n"] += idle
                a["min"] = 0
        self.cur_sec = sec
        self.cur_counts = Counter()

    def ignore(self):
        with self.lock:
            self.ignored += 1

    @staticmethod
    def _bump(d, sec):
        d[sec] = d.get(sec, 0) + 1
        if len(d) > 24:
            for k in [k for k in d if k < sec - 15]:
                del d[k]

    def add(self, r):
        with self.lock:
            self.total += 1
            r["n"] = self.total
            t = r["type"]
            self.type_counts[t] += 1
            sec = int(r["ts"])
            nbytes = r.get("length", 0)
            self.total_bytes += nbytes
            if self.first_sec is None:
                self.first_sec = sec
            self._roll(sec)
            self.cur_counts[t] += 1
            if t not in self.agg:
                self.agg[t] = dict(n=0, sum=0, min=None, max=0, first=sec)
            b = self.buckets.get(sec)
            if b is None:
                b = self.buckets[sec] = Counter()
                for old in [k for k in self.buckets if k < sec - 3700]:
                    del self.buckets[old]
            b["_total"] += 1
            b["_bytes"] += nbytes
            b[t] += 1
            self.packets.append(r)
            src = r["src"]
            self.src_totals[src] += 1
            self._bump(self.src_sec.setdefault(src, {}), sec)
            self.src_first.setdefault(src, r["ts"])
            self.clock_seen.setdefault((r["domain"], r["clock"]), {})[src] = r["ts"]

            if t == "Sync":
                key = (src, r["clock"], r["domain"])
                h = self.sync_hosts.get(key)
                if h is None:
                    h = self.sync_hosts[key] = dict(
                        src=src, clock=r["clock"], domain=r["domain"],
                        version=r["version"], ifaces=set(), dst=set(),
                        count=0, first=r["ts"], last=r["ts"],
                        gaps=deque(maxlen=64), log=None)
                else:
                    h["gaps"].append(r["ts"] - h["last"])
                h["count"] += 1
                h["last"] = r["ts"]
                h["ifaces"].add(r["iface"])
                h["dst"].add(r["dst"])
                if r["log"] is not None:
                    h["log"] = r["log"]
                self._bump(self.sync_sec.setdefault(key, {}), sec)

            if t == "Delay_Req":
                key = (src, r["clock"], r["domain"])
                h = self.dreq_hosts.get(key)
                if h is None:
                    h = self.dreq_hosts[key] = dict(
                        src=src, clock=r["clock"], domain=r["domain"], count=0,
                        first=r["ts"], last=r["ts"], gaps=deque(maxlen=128),
                        declared=None, dst=set())
                else:
                    h["gaps"].append(r["ts"] - h["last"])
                h["count"] += 1
                h["last"] = r["ts"]
                h["dst"].add(r["dst"])
                h["declared"] = r["log"]       # None = 0x7F, the standard value
            elif t == "Delay_Resp":
                if r["log"] is not None:
                    self.dresp_log[(r["domain"], src)] = (r["log"], r["ts"])
                if r.get("req_clock"):
                    k = (r["domain"], r["req_clock"])
                    old = self.dresp_links.get(k)
                    cnt = old["count"] + 1 if old and old["master_clock"] == r["clock"] else 1
                    self.dresp_links[k] = dict(master_ip=src, master_clock=r["clock"],
                                               master_port=r["port"], req_port=r["req_port"],
                                               count=cnt, last=r["ts"])

    def _dreq_report(self, ann_rows, nowf):
        """Hosts whose Delay_Req interval differs from the Sync interval of the
        grandmaster of their domain.

        The logMessageInterval field of a Delay_Req is 0x7F (127) by the
        standard (IEEE 1588 Table 24: the real rate is set by the master's
        logMinDelayReqInterval in Delay_Resp), so that value is never treated as
        a mismatch and the interval is measured from arrival times instead."""
        def gm_sync(dom):
            masters = [r for r in ann_rows
                       if str(r["domain"]) == dom and r["role"] == "master"]
            cands = [h for h in self.sync_hosts.values()
                     if h["domain"] == dom and h["log"] is not None]
            if masters:
                for h in cands:
                    if h["src"] == masters[0]["src"]:
                        return h, "grandmaster (best Announce)"
            if cands:
                return max(cands, key=lambda h: h["count"]), "Sync sender (no Announce master seen)"
            return None, ""

        rows = []
        for h in self.dreq_hosts.values():
            dom = h["domain"]
            g, basis = gm_sync(dom)
            gaps = sorted(h["gaps"])
            n = len(gaps)
            obs = (gaps[n // 2] if n % 2 else (gaps[n // 2 - 1] + gaps[n // 2]) / 2.0) if n else None
            dr = self.dresp_log.get((dom, g["src"])) if g else None
            if dr is None:        # any master answering in this domain
                v = [x[0] for (d, _), x in self.dresp_log.items() if d == dom]
                dr = (v[0],) if v else None
            row = dict(src=h["src"], clock=h["clock"], mac=clock_mac(h["clock"]),
                       domain=dom, count=h["count"],
                       observed_ms=obs * 1000 if obs else None,
                       observed_rate=(1.0 / obs) if obs else None,
                       declared=h["declared"], last=h["last"],
                       gm=g["src"] if g else None, gm_basis=basis,
                       sync_log=g["log"] if g else None,
                       sync_ms=(2.0 ** g["log"]) * 1000 if g else None,
                       resp_log=dr[0] if dr else None, ratio=None,
                       status="ok", note="")
            idle = nowf - h["last"] > max(10.0, 5 * (obs or 0))
            if g is None:
                row.update(status="unknown", note="No Sync from a grandmaster seen in domain %s" % dom)
            elif n < 10:
                row.update(status="measuring", note="Need more Delay_Req (%d of 10 intervals)" % n)
            elif idle:
                row.update(status="idle", note="No Delay_Req recently")
            else:
                ratio = obs / (2.0 ** g["log"])
                row["ratio"] = ratio
                why = []
                if ratio < 0.7 or ratio > 1.43:
                    why.append("sends Delay_Req %s than the GM sends Sync (%.2g\u00d7)" % (
                        "faster" if ratio < 1 else "slower", 1 / ratio if ratio < 1 else ratio))
                if h["declared"] is not None and h["declared"] != g["log"]:
                    why.append("header interval field is %d, not the Sync interval %d"
                               % (h["declared"], g["log"]))
                if why:
                    row["status"] = "mismatch"
                    row["note"] = "; ".join(why)
                    if dr is not None and not (h["declared"] is not None and h["declared"] != g["log"]):
                        rr = obs / (2.0 ** dr[0])
                        if 0.7 <= rr <= 1.43:
                            row["note"] += (". Matches the interval the GM asks for in Delay_Resp "
                                            "(logMinDelayReqInterval %d), which is allowed by the standard" % dr[0])
            rows.append(row)
        order = {"mismatch": 0, "unknown": 1, "measuring": 2, "idle": 3, "ok": 4}
        rows.sort(key=lambda r: (order[r["status"]], r["domain"], r["src"]))
        return rows

    def snapshot(self, window, roll=True, ann_rows=None):
        nowf = time.time()
        now = int(nowf)

        def rate(d, first):
            w = max(1, min(5, now - int(first)))     # completed seconds
            return sum(d.get(s, 0) for s in range(now - w, now)) / float(w)

        with self.lock:
            if roll and self.cur_sec is not None:
                self._roll(now)           # count idle seconds up to now
            types = list(TYPE_ORDER) + sorted(
                t for t in self.type_counts if t not in TYPE_ORDER)
            type_stats = {}               # per message type: totals and per-second stats
            for t in types:
                a = self.agg.get(t)
                if a is None:
                    type_stats[t] = dict(total=0, rate=0, min=0, max=0, avg=0)
                    continue
                w = max(1, min(5, now - a["first"]))
                type_stats[t] = dict(
                    total=self.type_counts.get(t, 0),
                    rate=sum(self.buckets.get(s, {}).get(t, 0)
                             for s in range(now - w, now)) / float(w),
                    min=a["min"] or 0, max=a["max"],
                    avg=(a["sum"] / a["n"]) if a["n"] else 0)
            wb = max(1, min(5, now - self.first_sec)) if self.first_sec is not None else 1
            bps = 8.0 * sum(self.buckets.get(s, {}).get("_bytes", 0)
                            for s in range(now - wb, now)) / wb
            secs = range(now - window + 1, now + 1)
            series = {"_total": [self.buckets.get(s, {}).get("_total", 0)
                                 for s in secs]}
            for t in types:
                series[t] = [self.buckets.get(s, {}).get(t, 0) for s in secs]
            recent = sum(self.buckets.get(s, {}).get("_total", 0)
                         for s in range(now - 5, now))
            dreq = self._dreq_report(ann_rows or [], nowf)
            hosts = []
            for key, h in self.sync_hosts.items():
                gaps = h["gaps"]
                log = h["log"]
                hosts.append(dict(
                    src=h["src"], clock=h["clock"], domain=h["domain"],
                    version=h["version"], ifaces=sorted(h["ifaces"]),
                    dst=sorted(h["dst"]), sync_count=h["count"],
                    total_count=self.src_totals[h["src"]],
                    log=log, last=h["last"],
                    announced_rate=(2.0 ** -log) if log is not None else None,
                    sync_rate=rate(self.sync_sec.get(key, {}), h["first"]),
                    total_rate=rate(self.src_sec.get(h["src"], {}),
                                    self.src_first.get(h["src"], h["first"])),
                    observed_ms=(sum(gaps) / len(gaps) * 1000) if gaps else None))
            hosts.sort(key=lambda x: -x["sync_count"])
            return dict(total=self.total, ignored=self.ignored,
                        rate=recent / 5.0, types=types,
                        type_counts={t: self.type_counts.get(t, 0) for t in types},
                        series=series, sync_hosts=hosts, dreq_hosts=dreq, now=nowf,
                        total_bytes=self.total_bytes, bps=bps, type_stats=type_stats)

    def topology(self, ann_rows, me=None):
        """Per domain: every PTP device seen and the clock it is clocking off.

        Sources, best first: a Delay_Resp names the port it answers
        (requestingPortIdentity), so the device that receives it follows the
        clock that sent it; an Announce whose sender is the grandmaster is the
        root; a boundary clock is placed under the only clock announcing the
        same grandmaster one step closer; a unicast Delay_Req goes to its
        master; otherwise a Delay_Req sender is assumed to follow the domain's
        current best master."""
        def dkey(d):
            try:
                return (0, int(d))
            except ValueError:
                return (1, d)
        with self.lock:
            now = time.time()
            doms = ({str(r["domain"]) for r in ann_rows}
                    | {h["domain"] for h in self.sync_hosts.values()}
                    | {h["domain"] for h in self.dreq_hosts.values()}
                    | {d for d, _ in self.dresp_links})
            if me:
                doms.add(me["domain"])
            out = []
            for dom in sorted(doms, key=dkey):
                nodes = {}

                def node(clock):
                    n = nodes.get(clock)
                    if n is None:
                        n = nodes[clock] = dict(clock=clock, ips={}, ann=None, sync=None,
                                                dreq=None, link=None, me=False, sends=set())
                        n["ips"].update(self.clock_seen.get((dom, clock), {}))
                    return n

                def seen(n, ip, ts):
                    if ip and ts > n["ips"].get(ip, 0):
                        n["ips"][ip] = ts

                for r in ann_rows:
                    if str(r["domain"]) != dom:
                        continue
                    n = node(r["clock"])
                    if n["ann"] is None or r["age"] < n["ann"]["age"]:
                        n["ann"] = r
                    seen(n, r["src"], now - r["age"])
                    n["sends"].add("Announce")
                best = next((r for r in ann_rows
                             if str(r["domain"]) == dom and r["role"] == "master"), None)
                if best is None:          # GM not visible here: nearest live boundary clock
                    bcs = [r for r in ann_rows if str(r["domain"]) == dom
                           and r["role"] == "boundary" and not r["expired"]]
                    best = min(bcs, key=lambda r: (r["steps"], r["src"])) if bcs else None
                for h in self.sync_hosts.values():
                    if h["domain"] == dom:
                        n = node(h["clock"])
                        n["sync"] = h
                        seen(n, h["src"], h["last"])
                        n["sends"].add("Sync")
                for h in self.dreq_hosts.values():
                    if h["domain"] == dom:
                        n = node(h["clock"])
                        n["dreq"] = h
                        seen(n, h["src"], h["last"])
                        n["sends"].add("Delay_Req")
                for (d, rc), L in self.dresp_links.items():
                    if d != dom:
                        continue
                    n = node(rc)
                    n["link"] = L
                    m = node(L["master_clock"])
                    seen(m, L["master_ip"], L["last"])
                    m["sends"].add("Delay_Resp")
                if me and me["domain"] == dom:
                    n = node(me["clock"])
                    n["me"] = True
                    seen(n, me["ip"], now)
                    n["sends"].add("Delay_Req")

                by_ip = {}
                for n in nodes.values():
                    for ip in n["ips"]:
                        by_ip.setdefault(ip, n)
                for n in nodes.values():
                    ann, parent, via = n["ann"], None, ""
                    is_gm = bool(ann and ann["clock"] == ann["gm"])
                    if n["link"]:
                        parent = n["link"]["master_clock"]
                        via = "Delay_Resp from it answers this clock (%d seen)" % n["link"]["count"]
                    elif is_gm:
                        via = "Announce: this clock is the grandmaster"
                    elif ann and ann["steps"] > 0:
                        c = [x for x in nodes.values() if x is not n and x["ann"]
                             and x["ann"]["gm"] == ann["gm"]
                             and x["ann"]["steps"] == ann["steps"] - 1]
                        if len(c) == 1:
                            parent = c[0]["clock"]
                            via = "Announce steps removed %d \u2192 one step below it (inferred)" % ann["steps"]
                        elif c:
                            via = "Ambiguous: %d clocks one step closer to the GM" % len(c)
                        else:
                            via = ("Upstream master not visible on this segment "
                                   "(steps removed %d from GM %s)" % (ann["steps"], ann["gm"]))
                    elif n["dreq"] or n["me"]:
                        uni = [ip for ip in (n["dreq"]["dst"] if n["dreq"] else ())
                               if not ip.startswith("224.") and ip not in GROUPS
                               and not ip.lower().startswith("ff")]
                        tgt = next((by_ip[ip] for ip in uni if ip in by_ip), None)
                        if tgt is not None and tgt is not n:
                            parent, via = tgt["clock"], "Unicast Delay_Req sent to it"
                        elif best and best["clock"] != n["clock"]:
                            parent = best["clock"]
                            via = "Domain\u2019s current best master (inferred \u2013 no Delay_Resp to this clock seen)"
                        else:
                            via = "No master seen for this domain"
                    else:
                        via = ("Sends Sync but no Announce seen" if n["sync"]
                               else "Only seen answering Delay_Req")
                    if parent is not None and parent not in nodes:
                        parent = None
                    n["parent"], n["via"], n["is_gm"] = parent, via, is_gm

                def steps(n, guard=0):
                    if n["ann"]:
                        return n["ann"]["steps"]
                    p = nodes.get(n["parent"]) if n["parent"] else None
                    if p is None or guard > 32:
                        return None
                    s0 = steps(p, guard + 1)
                    return None if s0 is None else s0 + 1

                def gm_of(n, guard=0):
                    if n["ann"]:
                        return n["ann"]["gm"]
                    p = nodes.get(n["parent"]) if n["parent"] else None
                    return None if p is None or guard > 32 else gm_of(p, guard + 1)

                kids = {}
                for n in nodes.values():
                    kids.setdefault(n["parent"], []).append(n)

                def role(n):
                    master_like = bool(n["ann"] or n["sync"] or "Delay_Resp" in n["sends"])
                    follows = bool(n["link"] or n["dreq"] or n["me"])
                    if n["is_gm"]:
                        r = "Grandmaster"
                    elif master_like and (follows or (n["ann"] and n["ann"]["steps"] > 0)):
                        r = "Boundary clock"
                    elif master_like:
                        r = "Master"
                    else:
                        r = "Slave"
                    return r

                order = {"Grandmaster": 0, "Boundary clock": 1, "Master": 2, "Slave": 3}

                def sort_key(n):
                    a = n["ann"]
                    return (order[role(n)], a["rank"] if a and a["rank"] else 999,
                            min(n["ips"]) if n["ips"] else n["clock"])
                rows, done = [], set()

                def walk(n, depth):
                    if n["clock"] in done:
                        return
                    done.add(n["clock"])
                    a = n["ann"]
                    p = nodes.get(n["parent"]) if n["parent"] else None
                    ch = [c for c in kids.get(n["clock"], []) if c is not n]
                    last = max(n["ips"].values()) if n["ips"] else None
                    rows.append(dict(
                        depth=depth, clock=n["clock"], mac=clock_mac(n["clock"]),
                        parent_mac=clock_mac(p["clock"]) if p else None,
                        ips=sorted(n["ips"], key=lambda ip: -n["ips"][ip]),
                        role=role(n), me=n["me"],
                        parent_clock=p["clock"] if p else None,
                        parent_ip=(max(p["ips"], key=p["ips"].get) if p and p["ips"] else None),
                        via=n["via"], gm=gm_of(n), steps=steps(n),
                        followers=len(ch), sends=sorted(n["sends"]),
                        ann_role=("expired" if a and a.get("expired") else
                                  a["role"] if a else None),
                        age=(now - last) if last else None))
                    for c in sorted(ch, key=sort_key):
                        walk(c, depth + 1)
                roots = [n for n in nodes.values() if n["parent"] is None]
                for n in sorted(roots, key=sort_key):
                    walk(n, 0)
                for n in sorted(nodes.values(), key=sort_key):   # anything in a loop
                    walk(n, 0)
                cnt = Counter(r["role"] for r in rows)
                out.append(dict(domain=dom, rows=rows, counts=dict(cnt),
                                gm=best["gm"] if best else None,
                                master_ip=best["src"] if best else None,
                                gm_visible=bool(best and best["role"] == "master")))
            return out

    def dreq_rows(self, ann_rows):
        with self.lock:
            return self._dreq_report(ann_rows or [], time.time())

    def query_packets(self, limit, ptype, text):
        text = text.lower()
        out = []
        with self.lock:
            for r in reversed(self.packets):
                if ptype and r["type"] != ptype:
                    continue
                if text and text not in (
                        "%s %s %s %s %s" % (r["src"], r["dst"], r["clock"],
                                            r["iface"], r["type"])).lower():
                    continue
                out.append(r)
                if len(out) >= limit:
                    break
        return out


STATS = Stats()


# --------------------------------------------------------------------------
# Announce messages -> clocks ranked with the IEEE 1588 best master clock
# algorithm (BMCA, data set comparison of 1588-2008 clause 9.3.4)
# --------------------------------------------------------------------------
CLOCK_CLASS = {6: "primary reference, locked", 7: "primary reference, holdover",
               13: "application-specific, locked",
               14: "application-specific, holdover",
               52: "class 7, degraded (A)", 58: "class 14, degraded (A)",
               187: "class 7, degraded (B)", 193: "class 14, degraded (B)",
               248: "default / free-running", 255: "slave-only"}
ACCURACY = {0x20: "≤ 25 ns", 0x21: "≤ 100 ns", 0x22: "≤ 250 ns",
            0x23: "≤ 1 µs", 0x24: "≤ 2.5 µs", 0x25: "≤ 10 µs",
            0x26: "≤ 25 µs", 0x27: "≤ 100 µs", 0x28: "≤ 250 µs",
            0x29: "≤ 1 ms", 0x2A: "≤ 2.5 ms", 0x2B: "≤ 10 ms",
            0x2C: "≤ 25 ms", 0x2D: "≤ 100 ms", 0x2E: "≤ 250 ms",
            0x2F: "≤ 1 s", 0x30: "≤ 10 s", 0x31: "> 10 s", 0xFE: "unknown"}
TIME_SOURCE = {0x10: "atomic clock", 0x20: "GPS", 0x30: "terrestrial radio",
               0x40: "PTP", 0x50: "NTP", 0x60: "hand set", 0x90: "other",
               0xA0: "internal oscillator"}
# (mask in 16-bit flagField, short label, description)
ANN_FLAGS = [(0x0100, "alt", "alternate master (ignored by BMCA)"),
             (0x0400, "uc", "unicast"), (0x0008, "ptp", "PTP timescale"),
             (0x0004, "utc", "currentUtcOffset valid"),
             (0x0010, "time", "time traceable"),
             (0x0020, "freq", "frequency traceable"),
             (0x0001, "L61", "leap61"), (0x0002, "L59", "leap59")]


def class_name(c):
    return CLOCK_CLASS.get(c, "profile-specific / reserved")


class AnnounceStore:
    """Keeps the latest Announce data of every clock (per domain and sender
    port) and ranks them per domain: rank 1 is the current master, the others
    are its successors in BMCA order."""
    KEYNAMES = ["Priority1", "Clock class", "Clock accuracy", "Offset variance",
                "Priority2", "Grandmaster identity", "Steps removed",
                "Sender clock identity", "Sender port number"]

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.rec = {}
            self.events = deque(maxlen=20)
            self.last_master = {}

    def add(self, info, p, ts, iface, src, dst, transport):
        if info["version"] != 2 or len(p) < 64:
            return
        key = (int(info["domain"]), src, info["clock"], info["port"])
        with self.lock:
            r = self.rec.get(key)
            if r is None:
                r = self.rec[key] = dict(
                    domain=key[0], src=src, clock=info["clock"], port=info["port"],
                    count=0, first=ts, last=ts, gaps=deque(maxlen=32),
                    ifaces=set(), transport=transport)
            else:
                r["gaps"].append(ts - r["last"])
            r["count"] += 1
            r["last"] = ts
            r["ifaces"].add(iface)
            r.update(log=info["log"], flags=info["flags"],
                     utc_off=struct.unpack("!h", p[44:46])[0],
                     p1=p[47], cls=p[48], acc=p[49],
                     var=struct.unpack("!H", p[50:52])[0], p2=p[52],
                     gm=p[53:61].hex(":"),
                     steps=struct.unpack("!H", p[61:63])[0], tsrc=p[63])

    @classmethod
    def _fmt(cls, i, v):
        return "0x%02X" % v if i == 2 else "0x%04X" % v if i == 3 else str(v)

    @classmethod
    def _why(cls, above, key):
        """First BMCA criterion on which this clock loses to the one above."""
        for i, (a, b) in enumerate(zip(above, key)):
            if a != b:
                if i == 5:
                    return "Grandmaster identity tie-break"
                if i >= 7:
                    return "Sender identity tie-break (same grandmaster, same steps)"
                return "%s %s (rank above: %s)" % (cls.KEYNAMES[i], cls._fmt(i, b),
                                                   cls._fmt(i, a))
        return "Identical data set"

    def snapshot(self):
        now = time.time()
        with self.lock:
            fresh = {}                    # newest data set seen per grandmaster
            for r in self.rec.values():
                k = (r["domain"], r["gm"])
                if k not in fresh or r["last"] > fresh[k]["last"]:
                    fresh[k] = r
            bydom = {}
            for r in self.rec.values():
                ds = fresh[(r["domain"], r["gm"])]
                lim = max(3.0 * 2.0 ** (r["log"] if r["log"] is not None else 0), 3.0)
                age = now - r["last"]
                if r["clock"] != r["gm"] or r["steps"] > 0:
                    # boundary clock: relays the grandmaster's data set, so it
                    # is not a grandmaster candidate and is left out of the ranking
                    status = "boundary"
                elif age > lim:
                    status = "expired"
                elif r["flags"] & 0x0100 or ds["cls"] == 255:
                    status = "ineligible"
                else:
                    status = "ok"
                key = (ds["p1"], ds["cls"], ds["acc"], ds["var"], ds["p2"], r["gm"],
                       r["steps"], r["clock"], r["port"])
                bydom.setdefault(r["domain"], []).append((status, key, r, age, lim))
            order = {"ok": 0, "ineligible": 1, "expired": 2, "boundary": 3}
            rows = []
            for dom in sorted(bydom):
                items = sorted(bydom[dom], key=lambda x: (order[x[0]], x[1]))
                rank, above = 0, None
                for status, key, r, age, lim in items:
                    if status == "ok":
                        rank += 1
                        role = "master" if rank == 1 else "successor"
                        reason = ("Best clock in the domain (current master)"
                                  if above is None else self._why(above, key))
                        above = key
                    elif status == "ineligible":
                        role = "ineligible"
                        reason = ("Alternate-master flag set – not used by BMCA"
                                  if r["flags"] & 0x0100 else "Slave-only clock class")
                    elif status == "boundary":
                        role = "boundary"
                        reason = ("Boundary clock relaying grandmaster %s (steps removed %d) "
                                  "\u2013 not a grandmaster candidate, not ranked"
                                  % (r["gm"], r["steps"]))
                    else:
                        role = "expired"
                        reason = "No Announce for %d s (timeout %d s)" % (age, lim)
                    gaps = r["gaps"]
                    rows.append(dict(expired=age > lim,
                        domain=dom, rank=rank if status == "ok" else None, role=role,
                        reason=reason, src=r["src"], clock=r["clock"], port=r["port"],
                        gm=r["gm"], p1=r["p1"], cls=r["cls"], cls_name=class_name(r["cls"]),
                        acc=r["acc"], acc_name=ACCURACY.get(r["acc"], "profile / reserved"),
                        var=r["var"], p2=r["p2"], steps=r["steps"],
                        tsrc=r["tsrc"], tsrc_name=TIME_SOURCE.get(r["tsrc"], "reserved / profile"),
                        utc_off=r["utc_off"], log=r["log"], count=r["count"], age=age,
                        ifaces=sorted(r["ifaces"]),
                        observed_ms=(sum(gaps) / len(gaps) * 1000) if gaps else None,
                        flags=[[s, d] for m, s, d in ANN_FLAGS if r["flags"] & m]))
            for dom in sorted(bydom):                       # master change log
                live = [x for x in rows if x["domain"] == dom and x["role"] == "master"]
                ident = (live[0]["src"], live[0]["clock"], live[0]["port"],
                         live[0]["gm"]) if live else None
                old = self.last_master.get(dom, "unset")
                if ident != old and not (old == "unset" and ident is None):
                    name = lambda i: "%s (GM %s)" % (i[0], i[3])
                    if ident is None:
                        text = ("Domain %d: no live grandmaster (no current Announce from a "
                                "grandmaster itself)" % dom)
                    elif old in ("unset", None):
                        text = "Domain %d: master is %s" % (dom, name(ident))
                    else:
                        text = "Domain %d: master changed from %s to %s" % (
                            dom, name(old), name(ident))
                    self.events.append((now, text))
                    self.last_master[dom] = ident
            return dict(rows=rows, now=now,
                        events=[dict(t=t, text=x) for t, x in list(self.events)[-10:]])


ANNOUNCES = AnnounceStore()


# --------------------------------------------------------------------------
# Raw packets, kept as classic pcap records so the capture can be downloaded
# --------------------------------------------------------------------------
class PacketRing:
    """Raw frames of everything the sniffers saw (including our own Delay_Req
    transmissions), stored as ready-made pcap records.  The capture buffer
    (CaptureBuffer below) rolls the oldest ones over when it is full."""
    # classic pcap, little-endian, microsecond timestamps, DLT_EN10MB (Ethernet)
    HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def __init__(self, limit_bytes=100 * 1024 * 1024):
        self.lock = threading.Lock()
        self.limit = limit_bytes
        self.reset()

    def reset(self):
        with self.lock:
            self.recs = deque()
            self.size = 0
            self.dropped = 0
            self.skipped = 0

    def add(self, pkt, iface):
        raw = getattr(pkt, "original", None) or bytes(pkt)
        if Ether in pkt:
            frame = bytes(raw)
        elif type(pkt).__name__ == "Loopback" and len(raw) > 4:
            # lo0 on macOS/BSD is DLT_NULL: give it an Ethernet header so the
            # whole file can use one link type
            frame = bytes(12) + (b"\x86\xdd" if raw[4] >> 4 == 6 else b"\x08\x00") + bytes(raw[4:])
        else:
            with self.lock:
                self.skipped += 1
            return
        ns = ts_to_ns(pkt.time)
        rec = struct.pack("<IIII", ns // 1_000_000_000, (ns % 1_000_000_000) // 1000,
                          len(frame), len(frame)) + frame
        with self.lock:
            self.recs.append(rec)
            self.size += len(rec)

    def snapshot(self):
        with self.lock:
            return list(self.recs), self.size

    def info(self):
        with self.lock:
            return dict(packets=len(self.recs), bytes=self.size,
                        dropped=BUFFER.rolled_frames, skipped=self.skipped,
                        limit=BUFFER.limit)


PCAP = PacketRing()


# --------------------------------------------------------------------------
# One capture buffer for everything stored per packet: the raw frames (for
# the .pcap download) and the decoded rows (for the packet list).  When it is
# full the oldest data is rolled over to make room for new packets.
# Summaries (counters, charts, host / clock tables) are not part of it.
# --------------------------------------------------------------------------
ROW_COST = 700         # approx. memory of one decoded packet-list row (bytes)
REC_OVERHEAD = 41      # Python object + deque slot per stored raw frame
MIN_BUFFER_MB, DEFAULT_BUFFER_MB = 1, 128


def _phys_ram():
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, ValueError, OSError):
        pass
    if sys.platform.startswith("win"):
        try:
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong),
                            ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                            ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong),
                            ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong),
                            ("ae", ctypes.c_ulonglong)]
            m = MS()
            m.len = ctypes.sizeof(MS)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return m.total
        except Exception:
            pass
    return None


class CaptureBuffer:
    def __init__(self, limit_mb=DEFAULT_BUFFER_MB):
        self.limit = limit_mb * 1024 * 1024
        self.reset()

    def reset(self):
        self.rolled_frames = 0
        self.rolled_rows = 0

    @staticmethod
    def max_mb():
        ram = _phys_ram()
        return max(MIN_BUFFER_MB, int(ram * 0.75 / 1048576)) if ram else 65536

    def _used(self):
        return (PCAP.size + len(PCAP.recs) * REC_OVERHEAD
                + len(STATS.packets) * ROW_COST)

    def enforce(self):
        """Drop the oldest stored data (raw frame or decoded row, whichever is
        older) until everything fits in the buffer again."""
        with STATS.lock, PCAP.lock:
            used = self._used()
            if used <= self.limit:
                return
            rows, recs = STATS.packets, PCAP.recs
            while used > self.limit and (rows or recs):
                tr = rows[0]["ts"] if rows else float("inf")
                if recs:
                    sec, usec = struct.unpack_from("<II", recs[0])
                    tp = sec + usec / 1e6
                else:
                    tp = float("inf")
                if recs and tp <= tr:
                    r = recs.popleft()
                    PCAP.size -= len(r)
                    used -= len(r) + REC_OVERHEAD
                    self.rolled_frames += 1
                else:
                    rows.popleft()
                    used -= ROW_COST
                    self.rolled_rows += 1

    def set_mb(self, mb):
        try:
            mb = int(mb)
        except (TypeError, ValueError):
            return dict(ok=False, error="Buffer size must be a whole number of MB")
        hi = self.max_mb()
        if not MIN_BUFFER_MB <= mb <= hi:
            return dict(ok=False, error="Buffer size must be %d to %d MB (75 %% of this "
                                        "computer's memory)" % (MIN_BUFFER_MB, hi))
        self.limit = mb * 1024 * 1024
        self.enforce()
        return dict(ok=True, buffer=self.info())

    def info(self):
        with STATS.lock, PCAP.lock:
            oldest = []
            if STATS.packets:
                oldest.append(STATS.packets[0]["ts"])
            if PCAP.recs:
                sec, usec = struct.unpack_from("<II", PCAP.recs[0])
                oldest.append(sec + usec / 1e6)
            return dict(limit=self.limit, used=self._used(), max_mb=self.max_mb(),
                        frames=len(PCAP.recs), rows=len(STATS.packets),
                        rolled_frames=self.rolled_frames, rolled_rows=self.rolled_rows,
                        oldest=min(oldest) if oldest else None)


BUFFER = CaptureBuffer()


# --------------------------------------------------------------------------
# Optional PTP participation: slave-only ordinary clock, end-to-end delay
# --------------------------------------------------------------------------
class Slave:
    """Follows the best master in one domain, sends Delay_Req after Sync and
    records offset / path delay.  Timestamps are the capture (pcap) timestamps
    of received Sync / Delay_Resp and of our own transmitted Delay_Req, so
    accuracy is that of software timestamping."""

    def __init__(self, max_samples=50000):
        self.lock = threading.RLock()
        self.running = False
        self.sock = None
        self.cfg = {}
        self.ip = ""
        self.clock_id = bytes(8)
        self.clock_str = ""
        self.port = SLAVE_PORT_NUMBER
        self.last_error = ""
        self.events = deque(maxlen=25)
        self.samples = deque(maxlen=max_samples)   # (time, correction, delay, seq)
        self.sample_total = 0
        self._stat_key = None
        self._stat_val = None
        self._init_state()

    def _init_state(self):
        self.masters = {}
        self.master = None            # (ip, clockIdentity, portNumber)
        self.pend_sync = None
        self.last_sync = None
        self.pending = {}
        self.dreq_seq = 0
        self.last_dreq_ns = 0
        self.sync_log = None
        self.master_dreq_log = None
        self.counts = Counter()
        self.gm_time = None           # last origin timestamp the master gave us

    def _event(self, text):
        self.events.append((time.time(), text))

    # -- control ------------------------------------------------------------
    def start_from_request(self, body):
        try:
            domain = int(body.get("domain", 0))
            if not 0 <= domain <= 127:
                raise ValueError
        except (TypeError, ValueError):
            return dict(ok=False, error="Domain must be a number from 0 to 127")
        iface = str(body.get("iface", ""))
        dreq = str(body.get("dreq", "auto"))
        if dreq not in ("auto", "sync"):
            try:
                if not -7 <= int(dreq) <= 7:
                    raise ValueError
            except ValueError:
                return dict(ok=False, error="Bad Delay_Req rate")
        force = str(body.get("force_master", "") or "").strip()
        if force and not _valid_ip(force):
            return dict(ok=False, error="'Only follow master IP' is not a valid IPv4 address")
        try:
            ttl = int(body.get("ttl", 1))
            if not 1 <= ttl <= MAX_TTL:
                raise ValueError
        except (TypeError, ValueError):
            return dict(ok=False, error="TTL must be a whole number from 1 to %d" % MAX_TTL)
        cfg = dict(domain=domain, iface=iface, dreq=dreq, ttl=ttl,
                   unicast=bool(body.get("unicast")),
                   timescale="tai" if body.get("timescale") == "tai" else "utc",
                   force_master=force)
        return self.start(cfg)

    def start(self, cfg):
        with self.lock:
            if self.running:
                return dict(ok=False, error="Already in a domain - leave it first")
        iface = cfg["iface"]
        if CAP is None or iface not in CAP.active:
            return dict(ok=False, error="Start the capture on %s first (step 1); "
                                        "the slave uses its packet timestamps" % (iface or "an interface"))
        ips = iface_ipv4s(iface)
        if not ips:
            return dict(ok=False, error="%s has no IPv4 address, cannot send Delay_Req" % iface)
        mac = iface_mac(iface)
        try:
            mb = bytes.fromhex(mac.replace(":", "").replace("-", ""))
            if len(mb) != 6:
                raise ValueError
        except Exception:
            mb = os.urandom(6)
        clock_id = mb[:3] + b"\xff\xfe" + mb[3:]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((ips[0], 0))          # ephemeral port: never steals traffic
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(ips[0]))
            ttl = int(cfg.get("ttl", 1))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)   # unicast Delay_Req
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        except Exception as e:
            return dict(ok=False, error="Could not open send socket on %s: %s" % (iface, e))
        self._begin(cfg, ips[0], clock_id, sock)
        return dict(ok=True)

    def _begin(self, cfg, ip, clock_id, sock):
        with self.lock:
            self.cfg = cfg
            self.ip = ip
            self.clock_id = clock_id
            self.clock_str = clock_id.hex(":")
            self.sock = sock
            self._init_state()
            self.samples.clear()
            self.sample_total = 0
            self._stat_key = None
            self.last_error = ""
            self.events.clear()
            self.running = True
            self._event("Joined domain %d on %s as %s (%s), TTL %d"
                        % (cfg["domain"], cfg["iface"], self.clock_str, ip,
                           cfg.get("ttl", 1)))

    def stop(self):
        with self.lock:
            if self.sock is not None:
                try:
                    self.sock.close()
                except Exception:
                    pass
            self.sock = None
            if self.running:
                self._event("Left domain")
            self.running = False

    def reset_samples(self):
        with self.lock:
            self.samples.clear()
            self.sample_total = 0
            self._stat_key = None
            self.counts = Counter()

    # -- packet input -------------------------------------------------------
    def on_tx(self, iface, info, ts_ns):
        """Our own Delay_Req seen leaving the interface -> precise t3."""
        with self.lock:
            if (not self.running or iface != self.cfg.get("iface")
                    or info["type"] != "Delay_Req"
                    or info["clock"] != self.clock_str or info["port"] != self.port):
                return
            pr = self.pending.get(info["seq"])
            if pr is not None:
                pr["t3"] = ts_ns

    def on_packet(self, iface, info, p, ts_ns, src, transport):
        try:
            with self.lock:
                if (not self.running or iface != self.cfg["iface"]
                        or info["version"] != 2 or not transport.startswith("UDP")
                        or int(info["domain"]) != self.cfg["domain"]):
                    return
                t = info["type"]
                now = ts_ns / 1e9
                if t == "Announce":
                    self._announce(info, p, now, src)
                elif t == "Sync":
                    self._select(now)
                    self._sync(info, p, ts_ns, src)
                elif t == "Follow_Up":
                    self._follow_up(info, p, ts_ns, src)
                elif t == "Delay_Resp":
                    self._delay_resp(info, p, ts_ns)
        except Exception as e:
            self.last_error = "%s: %s" % (type(e).__name__, e)

    # -- protocol -----------------------------------------------------------
    def _announce(self, info, p, now, src):
        if len(p) < 64:
            return
        flags = info["flags"]
        key = (src, info["clock"], info["port"])
        self.masters[key] = dict(
            ip=src, clock=info["clock"], port=info["port"], seen=now,
            log=info["log"], utc_off=struct.unpack("!h", p[44:46])[0],
            utc_valid=bool(flags & 0x0004), ptp_ts=bool(flags & 0x0008),
            p1=p[47], cls=p[48], acc=p[49],
            var=struct.unpack("!H", p[50:52])[0], p2=p[52],
            gm=p[53:61].hex(":"), steps=struct.unpack("!H", p[61:63])[0],
            tsrc=p[63])
        self.counts["announce"] += 1
        self._select(now)

    def _select(self, now):
        """Simplified best-master selection among live Announce senders."""
        force = self.cfg.get("force_master", "")
        best, bestrank = None, None
        for key in list(self.masters):
            m = self.masters[key]
            age = now - m["seen"]
            if age > 60:
                del self.masters[key]
                continue
            lim = max(3.0 * (2.0 ** (m["log"] if m["log"] is not None else 0)), 3.0)
            if age > lim or (force and m["ip"] != force):
                continue
            rank = (m["p1"], m["cls"], m["acc"], m["var"], m["p2"], m["gm"],
                    m["steps"], key)
            if bestrank is None or rank < bestrank:
                best, bestrank = key, rank
        if best != self.master:
            old = self.master
            self.master = best
            self.pend_sync = self.last_sync = None
            self.pending.clear()
            self.master_dreq_log = None
            if best:
                m = self.masters[best]
                self._event("Following master %s (%s), grandmaster %s, priority1 %d, class %d"
                            % (m["ip"], m["clock"], m["gm"], m["p1"], m["cls"]))
            elif old:
                self._event("Lost master %s (Announce timeout)" % old[0])

    def _from_master(self, info, src):
        return self.master == (src, info["clock"], info["port"])

    def _adj_ns(self):
        """Master timestamps are on the PTP (TAI) timescale; convert to UTC when
        the local clock is UTC."""
        m = self.masters.get(self.master)
        if self.cfg.get("timescale") == "utc" and m and m["ptp_ts"]:
            return m["utc_off"] * 1_000_000_000
        return 0

    def _sync(self, info, p, ts_ns, src):
        if not self._from_master(info, src) or len(p) < 44:
            return
        self.counts["sync"] += 1
        if info["log"] is not None:
            self.sync_log = info["log"]
        corr = info["corr"] / 65536.0
        if info["flags"] & 0x0200:                      # twoStepFlag
            self.pend_sync = dict(seq=info["seq"], t2=ts_ns, corr=corr)
        else:
            self._sync_done(ptp_ts_ns(p[34:44]), ts_ns, corr, ts_ns)

    def _follow_up(self, info, p, ts_ns, src):
        ps = self.pend_sync
        if (not self._from_master(info, src) or ps is None
                or ps["seq"] != info["seq"] or len(p) < 44):
            return
        self.pend_sync = None
        self.counts["follow_up"] += 1
        self._sync_done(ptp_ts_ns(p[34:44]), ps["t2"],
                        ps["corr"] + info["corr"] / 65536.0, ts_ns)

    def _sync_done(self, t1, t2, corr, now_ns):
        m = self.masters.get(self.master)
        if m:       # raw time as given by the GM (PTP/TAI for a ptpTimescale GM)
            self.gm_time = dict(t1=t1, recv=time.time(), utc_off=m["utc_off"],
                                ptp_ts=m["ptp_ts"], ip=m["ip"], gm=m["gm"])
        t1 -= self._adj_ns()
        self.last_sync = dict(ms=(t2 - t1) - corr)      # master->slave incl. offset
        self._maybe_send_dreq(now_ns)

    def _maybe_send_dreq(self, now_ns):
        if self.sock is None or self.master is None or self.last_sync is None:
            return
        for seq in [s for s, pr in self.pending.items() if now_ns - pr["sent"] > 5e9]:
            del self.pending[seq]
            self.counts["dreq_timeout"] += 1
        mode = self.cfg.get("dreq", "auto")
        if mode != "sync":
            if mode == "auto":
                lg = self.master_dreq_log
                if lg is None:
                    lg = self.sync_log if self.sync_log is not None else 0
            else:
                lg = int(mode)
            lg = max(-7, min(7, lg))
            if now_ns - self.last_dreq_ns < 0.9 * (2.0 ** lg) * 1e9:
                return
        if len(self.pending) >= 16:
            return
        self.dreq_seq = (self.dreq_seq + 1) & 0xFFFF
        seq = self.dreq_seq
        domain = self.cfg["domain"]
        dest = ((self.master[0] if self.cfg.get("unicast") else group_for_domain(domain)), 319)
        msg = build_delay_req(domain, self.clock_id, self.port, seq,
                              bool(self.cfg.get("unicast")))
        self.pending[seq] = dict(t3=now_ns, sent=now_ns, ms=self.last_sync["ms"])
        self.last_dreq_ns = now_ns
        try:
            self.sock.sendto(msg, dest)
            self.counts["dreq_tx"] += 1
        except OSError as e:
            self.pending.pop(seq, None)
            self.last_error = "send failed: %s" % e

    def _delay_resp(self, info, p, ts_ns):
        if (self.master is None or len(p) < 54
                or (info["clock"], info["port"]) != (self.master[1], self.master[2])
                or p[44:52] != self.clock_id
                or struct.unpack("!H", p[52:54])[0] != self.port):
            return                                      # not an answer to us
        self.counts["dresp_rx"] += 1
        if info["log"] is not None:
            self.master_dreq_log = info["log"]          # logMinDelayReqInterval
        pr = self.pending.pop(info["seq"], None)
        if pr is None:
            self.counts["dresp_late"] += 1
            return
        t4 = ptp_ts_ns(p[34:44]) - self._adj_ns()
        sm = (t4 - pr["t3"]) - info["corr"] / 65536.0   # slave->master incl. -offset
        ms = pr["ms"]
        delay = (ms + sm) / 2.0
        offset = (ms - sm) / 2.0                        # slave clock minus master
        self.samples.append((ts_ns / 1e9, -offset, delay, info["seq"]))
        self.sample_total += 1

    # -- reporting ----------------------------------------------------------
    def _stats(self):
        if self._stat_key != self.sample_total:
            self._stat_val = dict(corr=calc_stats([s[1] for s in self.samples]),
                                  delay=calc_stats([s[2] for s in self.samples]))
            self._stat_key = self.sample_total
        return self._stat_val

    def _gm_time_view(self, now):
        """Time currently given by the GM: last origin timestamp carried forward
        by the local elapsed time, shown as TAI and as UTC (TAI - utcOffset)."""
        g = self.gm_time
        if not g or not self.running:
            return None
        age = now - g["recv"]
        tai = g["t1"] + int(age * 1e9)
        utc = tai - g["utc_off"] * 1_000_000_000
        return dict(tai=fmt_ptp_time(tai), utc=fmt_ptp_time(utc),
                    tai_ns=str(tai), utc_ns=str(utc), utc_off=g["utc_off"],
                    ptp_ts=g["ptp_ts"], age=age, gm=g["gm"], ip=g["ip"])

    def snapshot(self):
        with self.lock:
            now = time.time()
            if self.running:
                self._select(now)
            m = self.masters.get(self.master) if self.master else None
            master = None
            if m:
                master = dict(ip=m["ip"], clock=m["clock"], port=m["port"],
                              gm=m["gm"], p1=m["p1"], p2=m["p2"], cls=m["cls"],
                              acc=m["acc"], steps=m["steps"], utc_off=m["utc_off"],
                              ptp_ts=m["ptp_ts"], age=now - m["seen"])
            if not self.running:
                state = "stopped"
            elif master is None:
                state = "listening"
            elif self.last_sync is None:
                state = "waiting_sync"
            elif not self.samples:
                state = "waiting_delay"
            else:
                state = "measuring"
            tail = list(self.samples)[-600:]
            last = self.samples[-1] if self.samples else None
            return dict(
                running=self.running, state=state, cfg=dict(self.cfg),
                error=self.last_error, ours=dict(clock=self.clock_str,
                                                 port=self.port, ip=self.ip),
                master=master, counts=dict(self.counts),
                gm_time=self._gm_time_view(now),
                last=(dict(corr=last[1], delay=last[2]) if last else None),
                series=dict(t=[s[0] for s in tail], corr=[s[1] for s in tail],
                            delay=[s[2] for s in tail]),
                stats=self._stats(),
                events=[dict(t=t, text=x) for t, x in list(self.events)[-8:]])


SLAVE = Slave()


# --------------------------------------------------------------------------
# Capture control
# --------------------------------------------------------------------------
def join_groups(iface, ip):
    """Join the four PTP multicast groups (IGMP) on one interface."""
    socks = []
    try:
        for g in GROUPS:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            socks.append(s)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            gb = socket.inet_aton(g)
            if sys.platform.startswith("linux"):
                mreq = struct.pack("4s4si", gb, socket.inet_aton(ip),
                                   socket.if_nametoindex(iface))
            else:
                mreq = gb + socket.inet_aton(ip)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except Exception:
        for s in socks:
            s.close()
        raise
    return socks


# --------------------------------------------------------------------------
# Multicast membership checks: IGMP on the wire + the OS membership table
# --------------------------------------------------------------------------
IGMP_QUERY_INTERVAL = 125        # default IGMP query interval (s)
QUERIER_HOLD = 260               # a querier counts as present this long after a query
KEEPALIVE_AFTER = 130            # no query for this long -> refresh our joins
KEEPALIVE_EVERY = 60             # ... every this many seconds
RETRY_FAILED_JOIN = 10           # retry a join that failed (e.g. no IPv4 yet)


def parse_igmp(raw):
    """IPv4 packet (bytes) carrying IGMP -> dict(kind, version, group, groups)
    where groups is [(group, 'join' | 'leave' | 'report')]."""
    if len(raw) < 20:
        return None
    ihl = (raw[0] & 0x0F) * 4
    tot = struct.unpack("!H", raw[2:4])[0]
    ig = raw[ihl:tot] if ihl < tot <= len(raw) else raw[ihl:]
    if len(ig) < 8:
        return None
    t = ig[0]
    if t == 0x11:                                   # membership query
        ver = 3 if len(ig) >= 12 else (1 if ig[1] == 0 else 2)
        g = socket.inet_ntoa(ig[4:8])
        return dict(kind="query", version=ver, group=g, general=g == "0.0.0.0", groups=[])
    if t in (0x12, 0x16):                           # v1 / v2 report
        return dict(kind="report", version=1 if t == 0x12 else 2,
                    groups=[(socket.inet_ntoa(ig[4:8]), "join")])
    if t == 0x17:                                   # v2 leave
        return dict(kind="leave", version=2, groups=[(socket.inet_ntoa(ig[4:8]), "leave")])
    if t == 0x22:                                   # v3 report: group records
        n = struct.unpack("!H", ig[6:8])[0]
        off, groups = 8, []
        for _ in range(n):
            if off + 8 > len(ig):
                break
            rt, aux = ig[off], ig[off + 1]
            ns = struct.unpack("!H", ig[off + 2:off + 4])[0]
            g = socket.inet_ntoa(ig[off + 4:off + 8])
            if rt in (2, 4) or (rt in (1, 3, 5) and ns):  # EXCLUDE mode, or INCLUDE with sources
                act = "join"
            elif rt in (1, 3):                            # INCLUDE {} = not a member
                act = "leave"
            else:
                act = "report"
            groups.append((g, act))
            off += 8 + 4 * ns + 4 * aux
        return dict(kind="report", version=3, groups=groups)
    return None


def _parse_proc_igmp(text):
    """Linux /proc/net/igmp -> ({device: set(groups)}, {device: IGMP version})."""
    groups, ver, dev = {}, {}, None
    fmt = "<I" if sys.byteorder == "little" else ">I"
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
        if not line[0].isspace():
            parts = line.split()
            if len(parts) < 2:
                continue
            dev = parts[1].rstrip(":")
            m = re.search(r"\bV(\d)\b", line)
            ver[dev] = int(m.group(1)) if m else None
            groups.setdefault(dev, set())
        elif dev is not None:
            h = line.split()[0]
            if re.fullmatch(r"[0-9A-Fa-f]{8}", h):
                groups[dev].add(socket.inet_ntoa(struct.pack(fmt, int(h, 16))))
    return groups, ver


def _parse_netstat_g(text):
    """macOS / BSD `netstat -g` -> {interface: set(IPv4 groups)}."""
    groups = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            groups.setdefault(parts[-1], set()).add(parts[0])
    return groups


def _parse_netsh_joins(text):
    """Windows `netsh interface ipv4 show joins` -> {'#index' and name: set}."""
    groups, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^\S[^:]*?\s(\d+):\s*(.+?)\s*$", line)
        if m:
            cur = set()
            groups["#" + m.group(1)] = cur
            groups[m.group(2)] = cur
            continue
        parts = line.split()
        if cur is not None and parts and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[-1]):
            cur.add(parts[-1])
    return groups


_OSM_CACHE = {"t": 0.0, "v": None}


def os_mcast_memberships():
    """What the operating system says this host has joined:
    ({interface: set(groups)}, {interface: IGMP version}) or None if unknown.
    Cached for 5 s."""
    now = time.time()
    if now - _OSM_CACHE["t"] < 5:
        return _OSM_CACHE["v"]
    res = None
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/net/igmp") as f:
                res = _parse_proc_igmp(f.read())
        elif sys.platform == "darwin" or "bsd" in sys.platform:
            out = subprocess.run(["netstat", "-g", "-n"], capture_output=True,
                                 text=True, timeout=5).stdout
            ver = {}
            try:
                v = subprocess.run(["sysctl", "-n", "net.inet.igmp.default_version"],
                                   capture_output=True, text=True, timeout=3).stdout.strip()
                if v.isdigit():
                    ver["*"] = int(v)
            except Exception:
                pass
            res = (_parse_netstat_g(out), ver)
        elif sys.platform.startswith("win"):
            out = subprocess.run(["netsh", "interface", "ipv4", "show", "joins"],
                                 capture_output=True, text=True, timeout=8).stdout
            res = (_parse_netsh_joins(out), {})
    except Exception:
        res = None
    _OSM_CACHE.update(t=now, v=res)
    return res


def _os_names(iface):
    """Names the OS may use for this interface in its membership table."""
    names = {iface}
    if sys.platform.startswith("win"):
        dev = _find_dev(iface)
        for a in ("name", "description", "network_name"):
            v = getattr(dev, a, None)
            if v:
                names.add(str(v))
        idx = getattr(dev, "index", None)
        if idx is not None:
            names.add("#%s" % idx)
    return names


class McastMonitor:
    """Per capture interface: did the OS join the PTP groups, did this host's
    IGMP join reports go out, is there an IGMP querier on the network, and are
    PTP packets arriving.  Also keeps joins alive when there is no querier."""

    def __init__(self):
        self.lock = threading.Lock()
        self.keepalive = True
        self.ifs = {}

    def reset_counts(self):
        with self.lock:
            for d in self.ifs.values():
                d.update(frames=0, ptp=0, last_ptp=None)

    @staticmethod
    def _new(name):
        return dict(name=name, ip=None, started=time.time(), join_error=None,
                    joined_at=None, rejoins=0, auto_rejoins=0, last_rejoin=None,
                    last_try=None, frames=0, ptp=0, last_ptp=None, queriers={},
                    own={}, others={}, igmp=0)

    def begin(self, name):
        """Capture starting on this interface (before the groups are joined)."""
        with self.lock:
            self.ifs[name] = self._new(name)

    def joined(self, name, ip, error):
        with self.lock:
            d = self.ifs.setdefault(name, self._new(name))
            d.update(ip=ip, join_error=error, last_try=time.time(),
                     joined_at=None if error else time.time())

    def on_rejoin(self, name, ip, auto, error):
        with self.lock:
            d = self.ifs.setdefault(name, self._new(name))
            now = time.time()
            d.update(ip=ip or d["ip"], join_error=error, last_try=now)
            if not error:
                d["joined_at"] = d["joined_at"] or now
                d["last_rejoin"] = now
                d["rejoins"] += 1
                if auto:
                    d["auto_rejoins"] += 1

    def frame(self, name):
        with self.lock:
            d = self.ifs.get(name)
            if d is not None:
                d["frames"] += 1

    def ptp(self, name, ts):
        with self.lock:
            d = self.ifs.get(name)
            if d is not None:
                d["ptp"] += 1
                d["last_ptp"] = ts

    def igmp(self, name, src, raw, ts, own):
        p = parse_igmp(raw)
        if p is None:
            return
        with self.lock:
            d = self.ifs.get(name)
            if d is None:
                return
            d["igmp"] += 1
            if own or (d["ip"] and src == d["ip"]):
                if p["kind"] != "query":
                    for g, act in p["groups"]:
                        o = d["own"].get(g, dict(count=0))
                        o.update(last=ts, action=act, version=p["version"],
                                 count=o["count"] + 1)
                        d["own"][g] = o
            elif p["kind"] == "query":
                q = d["queriers"].setdefault(src, dict(count=0, last_general=None))
                q.update(last=ts, version=p["version"], count=q["count"] + 1)
                if p["general"]:
                    q["last_general"] = ts
            else:
                for g, act in p["groups"]:
                    if g in GROUPS:
                        o = d["others"].setdefault(g, {})
                        if act == "join":
                            o[src] = ts
                        else:
                            o.pop(src, None)

    def _querier(self, d, now):
        live = [(q["last"], ip, q) for ip, q in d["queriers"].items()
                if now - q["last"] < QUERIER_HOLD]
        if not live:
            return None
        last, ip, q = max(live)
        return dict(ip=ip, version=q["version"], age=now - last, count=q["count"])

    def tick(self, cap, bpf_has_igmp):
        """Called every few seconds: retry failed joins, refresh joins when no
        IGMP querier keeps the switches' snooping tables up to date."""
        if cap is None or not cap.running:
            return
        now = time.time()
        todo = []
        with self.lock:
            for name in list(cap.joins):
                d = self.ifs.get(name)
                if d is None:
                    continue
                if d["join_error"] or not d["joined_at"]:
                    if now - (d["last_try"] or 0) >= RETRY_FAILED_JOIN:
                        todo.append(name)
                    continue
                if not (self.keepalive and bpf_has_igmp):
                    continue
                q = self._querier(d, now)
                if q is None and now - d["started"] >= KEEPALIVE_AFTER and \
                        now - (d["last_rejoin"] or d["joined_at"]) >= KEEPALIVE_EVERY:
                    todo.append(name)
        if todo:
            cap.rejoin(todo, auto=True)

    def snapshot(self, active, bpf_has_igmp):
        now = time.time()
        osm = os_mcast_memberships()
        out = []
        with self.lock:
            for name in active:
                d = self.ifs.get(name)
                if d is None:
                    continue
                os_groups, os_ver = None, None
                if osm is not None:
                    gmap, vmap = osm
                    os_groups = set()
                    for n in _os_names(name):
                        os_groups |= gmap.get(n, set())
                        if vmap.get(n):
                            os_ver = vmap[n]
                    os_ver = os_ver or vmap.get("*")
                groups = []
                for g in GROUPS:
                    o = d["own"].get(g)
                    groups.append(dict(
                        group=g, os=(g in os_groups) if os_groups is not None else None,
                        report_age=(now - o["last"]) if o else None,
                        report_action=o["action"] if o else None,
                        report_version=o["version"] if o else None,
                        others=len(d["others"].get(g, {}))))
                q = self._querier(d, now)
                up = now - d["started"]
                hints = []
                missing = [x["group"] for x in groups if x["os"] is False]
                if d["join_error"]:
                    hints.append(("bad", "Joining the PTP groups failed: %s. Retrying every %d s."
                                  % (d["join_error"], RETRY_FAILED_JOIN)))
                elif missing and d["joined_at"] and now - d["joined_at"] > 2:
                    hints.append(("bad", "The operating system does not list %s as joined on %s. "
                                  "Press \u201cRe-join groups now\u201d; if it stays missing, check that "
                                  "%s is the address of this interface." % (", ".join(missing), name, d["ip"])))
                own_join = [x for x in groups if x["report_action"] == "join"]
                if bpf_has_igmp and d["joined_at"] and not d["join_error"]:
                    if not own_join and now - d["joined_at"] > 5:
                        hints.append(("warn", "No IGMP join report from this computer was seen on %s. "
                                      "The join may have gone out of a different interface \u2013 "
                                      "check that %s belongs to %s." % (name, d["ip"], name)))
                if bpf_has_igmp:
                    if q is None and up >= KEEPALIVE_AFTER:
                        hints.append(("warn", "No IGMP querier seen on this network in %d s. Switches with "
                                      "IGMP snooping usually stop (or never start) forwarding PTP multicast "
                                      "without one \u2013 enable an IGMP querier on the PTP VLAN, or turn IGMP "
                                      "snooping off there.%s" % (up, " Meanwhile this computer re-sends its "
                                      "join every %d s." % KEEPALIVE_EVERY if self.keepalive else "")))
                    elif q is None:
                        hints.append(("info", "Waiting for an IGMP query (queriers normally send one every "
                                      "%d s) \u2026 %d s so far." % (IGMP_QUERY_INTERVAL, up)))
                else:
                    hints.append(("info", "The capture filter does not include IGMP, so join reports and "
                                  "the querier cannot be checked (the default filter includes it)."))
                if d["ptp"] == 0 and up >= 15:
                    if d["frames"] == 0:
                        hints.append(("warn", "Nothing at all has arrived on %s yet (not even IGMP). Check "
                                      "the cable / link, that this is the port on the PTP network, and that "
                                      "the capture is running as root." % name))
                    elif q is not None and own_join and not missing:
                        hints.append(("warn", "This computer has joined and a querier (%s) is present, but no "
                                      "PTP packets arrive. Check that this port is in the PTP VLAN and that a "
                                      "grandmaster is running; the switch\u2019s IGMP snooping table should list "
                                      "this port for 224.0.1.129." % q["ip"]))
                    else:
                        hints.append(("warn", "No PTP packets on %s yet." % name))
                elif d["ptp"]:
                    hints.append(("ok", "Receiving PTP: %d packets, last %.0f s ago."
                                  % (d["ptp"], now - d["last_ptp"])))
                out.append(dict(
                    name=name, ip=d["ip"], groups=groups, os_known=os_groups is not None,
                    os_version=os_ver, querier=q, frames=d["frames"], ptp=d["ptp"],
                    last_ptp_age=(now - d["last_ptp"]) if d["last_ptp"] else None,
                    rejoins=d["rejoins"], auto_rejoins=d["auto_rejoins"],
                    last_rejoin_age=(now - d["last_rejoin"]) if d["last_rejoin"] else None,
                    joined_age=(now - d["joined_at"]) if d["joined_at"] else None,
                    error=d["join_error"], uptime=up, hints=hints))
        return dict(ifaces=out, keepalive=self.keepalive, igmp_in_filter=bpf_has_igmp)


MCAST = McastMonitor()


def make_handler(iface, my_mac):
    def handle(pkt):
        try:
            PCAP.add(pkt, iface)              # keep the raw frame for .pcap download
            MCAST.frame(iface)
        except Exception:
            pass
        try:
            process(pkt)
        finally:
            try:
                BUFFER.enforce()              # roll over the oldest data when full
            except Exception:
                pass

    def process(pkt):
        try:
            own = bool(Ether in pkt and my_mac and pkt[Ether].src.lower() == my_mac)
            if IP in pkt and int(getattr(pkt[IP], "proto", 0)) == 2:     # IGMP
                MCAST.igmp(iface, pkt[IP].src, bytes(pkt[IP]), float(pkt.time), own)
                return
            if UDP in pkt:
                payload = bytes(pkt[UDP].payload)
                if IP in pkt:
                    src, dst = pkt[IP].src, pkt[IP].dst
                    dscp = (int(pkt[IP].tos) >> 2) & 0x3F
                elif IPv6 in pkt:
                    src, dst = pkt[IPv6].src, pkt[IPv6].dst
                    dscp = (int(pkt[IPv6].tc) >> 2) & 0x3F
                else:
                    return
                transport = "UDP/%d" % pkt[UDP].dport
            elif Ether in pkt:
                dscp = None                       # layer-2 PTP has no IP header
                l2 = pkt[Dot1Q] if Dot1Q in pkt else pkt[Ether]
                if l2.type != 0x88F7:
                    return
                payload = bytes(l2.payload)
                src, dst, transport = pkt[Ether].src, pkt[Ether].dst, "L2"
            else:
                return
            info = parse_ptp(payload)
            if own:                       # our own transmissions: only used for t3
                if info is not None and SLAVE.running:
                    SLAVE.on_tx(iface, info, ts_to_ns(pkt.time))
                return
            if info is None:
                STATS.ignore()
                return
            if info["type"] == "Announce":
                ANNOUNCES.add(info, payload, float(pkt.time), iface, src, dst,
                              transport)
            if SLAVE.running:
                SLAVE.on_packet(iface, info, payload, ts_to_ns(pkt.time), src,
                                transport)
            info.pop("flags", None)
            info.pop("corr", None)
            info.update(ts=float(pkt.time), iface=iface, src=src, dst=dst,
                        transport=transport, length=len(pkt), dscp=dscp)
            STATS.add(info)
            MCAST.ptp(iface, info["ts"])
        except Exception:
            STATS.ignore()
    return handle


class Capture:
    def __init__(self, bpf, promisc):
        self.bpf, self.promisc = bpf, promisc
        self.lock = threading.Lock()
        self.sniffers, self.active = [], []
        self.joins = {}               # interface -> dict(ip, socks)
        self.running = False
        self.started_at = None

    @property
    def igmp_in_filter(self):
        return bool(re.search(r"\bigmp\b|proto\s+2\b", self.bpf or ""))

    def _join(self, name):
        """(ip, socks, error) - join the PTP groups on one interface."""
        ips = iface_ipv4s(name)
        if not ips:
            return None, [], "no IPv4 address on %s yet" % name
        try:
            return ips[0], join_groups(name, ips[0]), None
        except Exception as e:
            return ips[0], [], "could not join on %s (%s)" % (ips[0], e)

    def rejoin(self, names=None, auto=False):
        """Leave and join the PTP groups again so the OS sends fresh IGMP
        join reports (dropping the last membership first is the only way to
        make it send a new report)."""
        res = []
        with self.lock:
            for name in (names or list(self.joins)):
                j = self.joins.get(name)
                if j is None:
                    continue
                for sk in j["socks"]:
                    try:
                        sk.close()
                    except Exception:
                        pass
                ip, socks, err = self._join(name)
                j.update(ip=ip or j["ip"], socks=socks)
                MCAST.on_rejoin(name, ip, auto, err)
                res.append(dict(iface=name, ok=err is None, error=err))
        return dict(ok=bool(res) and all(r["ok"] for r in res), results=res)

    def start(self, ifaces):
        errors = []
        with self.lock:
            if self.running:
                return dict(ok=False, errors=["Capture is already running"])
            if not ifaces:
                return dict(ok=False, errors=["Select at least one interface"])
            for name in ifaces:
                mac = iface_mac(name)
                MCAST.begin(name)
                # start capturing first, so this host's own IGMP join reports
                # (sent the moment the groups are joined) are seen on the wire
                sn = AsyncSniffer(iface=name, filter=self.bpf,
                                  prn=make_handler(name, mac), store=False,
                                  promisc=self.promisc)
                sn.start()
                time.sleep(0.3)
                exc = getattr(sn, "exception", None)
                if exc or not sn.thread.is_alive():
                    errors.append("%s: capture failed to start (%s)"
                                  % (name, exc or "is this running as root?"))
                    continue
                ip, socks, err = self._join(name)
                if err:
                    errors.append("%s: %s \u2013 capturing anyway, the join is retried "
                                  "every %d s" % (name, err, RETRY_FAILED_JOIN))
                MCAST.joined(name, ip, err)
                self.sniffers.append(sn)
                self.joins[name] = dict(ip=ip, socks=socks)
                self.active.append(name)
            self.running = bool(self.active)
            if self.running:
                self.started_at = time.time()
            return dict(ok=self.running, errors=errors, active=self.active)

    def stop(self):
        SLAVE.stop()
        with self.lock:
            for sn in self.sniffers:
                try:
                    sn.stop()
                except Exception:
                    pass
            for j in self.joins.values():
                for s in j["socks"]:
                    s.close()
            self.sniffers, self.active, self.joins = [], [], {}
            self.running = False
            self.started_at = None


CAP = None


HIDE_REASONS = {"wifi": "Wi-Fi", "cellular": "cellular", "tunnel": "VPN / tunnel"}


def list_interfaces(show_all=False):
    """Active wired interfaces by default. With show_all, also the ones that are
    normally hidden (Wi-Fi, cellular, VPN/tunnel, link-down, loopback), each
    tagged with the reason in 'hidden'."""
    out = []
    for name in get_if_list():
        dev = _find_dev(name)
        label = name
        try:
            label = getattr(dev, "description", None) or getattr(dev, "name", None) or name
        except Exception:
            pass
        ips = iface_ipv4s(name)
        kind, up = iface_kind_up(name, dev, label)
        if _is_loopback(name, label, ips):
            reason = "loopback"
        elif kind is not None:
            reason = HIDE_REASONS[kind]
        elif up is False:
            reason = "link down"
        elif up is None and not ips:
            reason = "not active"
        else:
            reason = ""
        # never hide an interface we are already capturing on
        if reason and not show_all and name not in CAP.active:
            continue
        out.append(dict(name=name, label=label, ips=ips, hidden=reason,
                        ip=ips[0] if ips else "no IPv4",
                        mac=iface_mac(name) or "-",
                        state={True: "up", False: "down"}.get(up) or iface_state(name),
                        selected=name in CAP.active))
    return out


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if u.path == "/api/interfaces":
            return self._send(200, list_interfaces(q.get("all", ["0"])[0] == "1"))
        if u.path == "/api/state":
            window = max(30, min(3600, int(q.get("window", ["300"])[0])))
            ann = ANNOUNCES.snapshot()
            s = STATS.snapshot(window, roll=CAP.running, ann_rows=ann["rows"])
            me = None
            if SLAVE.running and SLAVE.cfg:
                me = dict(domain=str(SLAVE.cfg.get("domain")), clock=SLAVE.clock_str,
                          ip=SLAVE.ip)
            s["topology"] = STATS.topology(ann["rows"], me)
            s["mcast"] = MCAST.snapshot(CAP.active, CAP.igmp_in_filter)
            s.update(running=CAP.running, active=CAP.active, groups=GROUPS,
                     bpf=CAP.bpf, slave=SLAVE.snapshot(),
                     announce=ann, pcap=PCAP.info(), buffer=BUFFER.info(),
                     uptime=(time.time() - CAP.started_at) if CAP.started_at else 0)
            return self._send(200, s)
        if u.path == "/api/pcap":
            recs, size = PCAP.snapshot()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Disposition", 'attachment; filename="ptp_capture_%s.pcap"'
                             % time.strftime("%Y%m%d_%H%M%S"))
            self.send_header("Content-Length", str(len(PacketRing.HEADER) + size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(PacketRing.HEADER)
                for i in range(0, len(recs), 2000):
                    self.wfile.write(b"".join(recs[i:i + 2000]))
            except (BrokenPipeError, ConnectionResetError):
                pass                               # browser cancelled the download
            return
        if u.path == "/api/dreq.csv":
            ann = ANNOUNCES.snapshot()
            rows = STATS.dreq_rows(ann["rows"])
            if q.get("all", ["0"])[0] != "1":
                rows = [r for r in rows if r["status"] == "mismatch"]
            data = dreq_csv(rows).encode("utf-8-sig")       # BOM so Excel reads UTF-8
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="ptp_delay_req_check_%s.csv"'
                             % time.strftime("%Y%m%d_%H%M%S"))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/api/packets":
            limit = max(1, min(1000, int(q.get("limit", ["200"])[0])))
            return self._send(200, STATS.query_packets(
                limit, q.get("type", [""])[0], q.get("q", [""])[0]))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        # Requiring JSON blocks cross-site form posts from other web pages.
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self._send(415, {"error": "JSON required"})
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        if self.path == "/api/start":
            return self._send(200, CAP.start(body.get("interfaces", [])))
        if self.path == "/api/stop":
            CAP.stop()
            return self._send(200, {"ok": True})
        if self.path == "/api/clear":
            STATS.reset()
            ANNOUNCES.reset()
            PCAP.reset()
            BUFFER.reset()
            MCAST.reset_counts()
            SLAVE.reset_samples()
            return self._send(200, {"ok": True})
        if self.path == "/api/rejoin":
            if not CAP.running:
                return self._send(200, dict(ok=False, error="The capture is not running"))
            return self._send(200, CAP.rejoin())
        if self.path == "/api/igmp_keepalive":
            MCAST.keepalive = bool(body.get("on"))
            return self._send(200, dict(ok=True, keepalive=MCAST.keepalive))
        if self.path == "/api/buffer":
            return self._send(200, BUFFER.set_mb(body.get("mb")))
        if self.path == "/api/slave/start":
            return self._send(200, SLAVE.start_from_request(body))
        if self.path == "/api/slave/stop":
            SLAVE.stop()
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PTP Monitor</title>
<style>
:root{--bg:#f6f6f4;--card:#fff;--text:#1f1f1d;--muted:#6b6b66;--line:#e2e1dc;--accent:#185FA5;--ok:#1D9E75;--warn:#BA7517;--bad:#E24B4A;--mac:#7a52c7;--onfill:#fff;color-scheme:light}
/* theme: follows the system unless the page sets data-theme="light" / "dark" */
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#161615;--card:#212120;--text:#ececea;--muted:#9b9a94;--line:#3a3a37;--accent:#5aa2e6;--ok:#3cc29a;--warn:#e0a03c;--bad:#f06a69;--mac:#b39bf0;--onfill:#10110f;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#161615;--card:#212120;--text:#ececea;--muted:#9b9a94;--line:#3a3a37;--accent:#5aa2e6;--ok:#3cc29a;--warn:#e0a03c;--bad:#f06a69;--mac:#b39bf0;--onfill:#10110f;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1400px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:0 0 2px}h2{font-size:15px;margin:0 0 10px}h3{font-size:13px;margin:14px 0 6px}
.sub{color:var(--muted);margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
.row{display:flex;gap:14px;flex-wrap:wrap}.row>.card{flex:1 1 380px;margin-bottom:0}
.if{display:inline-flex;gap:8px;align-items:center;border:1px solid var(--line);border-radius:8px;padding:6px 10px;margin:0 8px 8px 0;cursor:pointer}
.if small{color:var(--muted)}.if .ipv4{color:var(--ok);font-weight:500}.if .macaddr{color:var(--mac)}.if .noip{color:var(--bad)}
.chip{display:inline-block;font-size:11px;border:1px solid var(--line);border-radius:6px;padding:0 5px;margin-right:3px;color:var(--muted)}
tr.dh td{background:var(--bg);font-weight:500;position:sticky;left:0}
tr.dh{cursor:pointer;user-select:none}tr.dh:hover td{background:var(--line)}
.caret{display:inline-block;width:14px;color:var(--muted);transition:transform .15s}tr.dh.closed .caret{transform:rotate(-90deg)}
.dhx{font-weight:400;color:var(--muted);font-size:12px}
.xall{font-size:12px;color:var(--accent);cursor:pointer;background:none;border:0;padding:0 4px}
.tree{white-space:nowrap}.tree i{display:inline-block;color:var(--muted);font-style:normal}
.role{display:inline-block;padding:0 7px;border-radius:9px;font-size:12px;border:1px solid var(--line)}
.role.gm{background:var(--ok);color:var(--onfill);border-color:var(--ok)}.role.bc{background:var(--accent);color:var(--onfill);border-color:var(--accent)}
.role.ma{border-color:var(--accent);color:var(--accent)}
tr.m td{background:rgba(29,158,117,.13)}
tr.x td{opacity:.55}
tr.bcrow td{background:rgba(24,95,165,.05)}
tr.hid td{color:var(--muted);padding-top:2px;padding-bottom:2px}
.mcbox{border-top:1px solid var(--line);margin-top:10px;padding-top:10px}
.gchip{display:inline-block;font-size:11px;border-radius:6px;padding:0 5px;margin:1px 3px 1px 0;border:1px solid var(--line)}
.gchip.y{color:var(--ok);border-color:var(--ok)}.gchip.n{color:var(--bad);border-color:var(--bad)}.gchip.u{color:var(--muted)}
.mchints div{font-size:12px;margin:4px 0;padding:4px 8px;border-left:3px solid var(--line)}
.mchints .bad{border-color:var(--bad)}.mchints .warn{border-color:var(--warn)}.mchints .ok{border-color:var(--ok)}.mchints .info{border-color:var(--accent)}
.tg{cursor:pointer;color:var(--accent);display:inline-block;width:16px;text-align:center;user-select:none}
.tg.c{transform:rotate(-90deg)}
td small{color:var(--muted)}
.why{color:var(--warn);font-size:11px;border:1px solid var(--warn);border-radius:8px;padding:0 6px;margin-left:4px;white-space:nowrap}
button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;padding:6px 14px;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--onfill)}
button:disabled{opacity:.45;cursor:default}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.kpi b{display:block;font-size:22px;font-weight:600}.kpi span{color:var(--muted);font-size:12px}
.kpi.s b{font-size:16px;overflow:hidden;text-overflow:ellipsis}
canvas{width:100%;height:210px;display:block}
canvas.tall{height:260px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.mini{border:1px solid var(--line);border-radius:8px;padding:8px 10px}
.mini h3{font-size:12px;margin:0 0 4px;display:flex;justify-content:space-between;font-weight:600}
.mini canvas{height:80px}
.mstats{display:flex;flex-wrap:wrap;gap:1px 12px;font-size:12px;color:var(--muted);margin-bottom:4px}
.mstats:empty{display:none}
.mstats b{color:var(--text);font-weight:600;font-variant-numeric:tabular-nums}
.lg{display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:12px;color:var(--text);background:var(--card);border:1px solid var(--line);border-radius:14px;padding:2px 10px;margin:0 6px 6px 0;cursor:pointer}
.lg.off{color:var(--muted);text-decoration:line-through}
.lg.off i{background:transparent!important;outline:1.5px solid var(--muted);outline-offset:-1.5px}
.lgx{font:inherit;font-size:12px;color:var(--accent);background:none;border:none;padding:2px 8px;margin:0 2px 6px 0;cursor:pointer}
.legend span{display:inline-flex;align-items:center;gap:4px;margin-right:12px;font-size:12px;color:var(--muted)}
.legend i{width:10px;height:10px;border-radius:2px;display:inline-block}
.tw{overflow:auto;max-height:430px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{position:sticky;top:0;background:var(--card);color:var(--muted);font-weight:500}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;color:#fff}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.msg{color:var(--bad);margin-top:6px;white-space:pre-line}
.tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
input[type=text],input[type=number],select{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text)}
.form{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.form label{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--muted)}
.empty{color:var(--muted);padding:12px 4px}
.sstats{max-width:760px}
.gmtime{border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin-bottom:10px;font-size:13px}.gmtime .mono{font-size:16px;font-weight:600}.gmtime table{width:auto}.gmtime td,.gmtime th{border:0;padding:2px 14px 2px 0}
.events{color:var(--muted);font-size:12px;margin-top:10px}
.events div{padding:1px 0}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--card)}
.seg button{border:0;border-radius:0;padding:5px 12px;font-size:12px;background:transparent;color:var(--muted)}
.seg button+button{border-left:1px solid var(--line)}
.seg button[aria-pressed="true"]{background:var(--accent);color:var(--onfill)}
.mac{color:var(--mac)}
.srch{display:inline-flex;align-items:center;gap:6px}
.srch input{width:300px;max-width:70vw}
tr.hit td{background:rgba(186,117,23,.14)}
mark{background:rgba(186,117,23,.35);color:inherit;border-radius:2px;padding:0 1px}
</style>
<script>
try{const t=localStorage.getItem('ptpTheme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t}catch(e){}
</script>
</head><body><main>
<div class="topbar"><h1>PTP Multicast Monitor</h1>
  <div class="seg" role="group" aria-label="Colour theme" id="themeSeg">
    <button data-theme-set="system" title="Follow the system light / dark setting">System</button>
    <button data-theme-set="light">Light</button>
    <button data-theme-set="dark">Dark</button>
  </div></div>
<div class="sub">Groups 224.0.1.129 &ndash; 224.0.1.132 &middot; UDP 319/320 and L2 (0x88F7)</div>

<div class="card">
  <h2>1. Choose interface(s) to enable</h2>
  <div class="tools" style="margin:-4px 0 8px">
    <span class="sub" id="ifHint" style="margin:0;font-size:12px"></span>
    <label style="font-size:12px"><input type="checkbox" id="showAll"> Show all interfaces (advanced)</label>
  </div>
  <div id="ifaces"></div>
  <div class="tools">
    <button id="bStart" class="primary">Start capture</button>
    <button id="bStop">Stop</button>
    <button id="bClear">Clear data</button>
    <button id="bPcap" disabled title="Download everything captured so far as a Wireshark/tcpdump compatible .pcap file">Download .pcap</button>
    <button id="bRefresh">Refresh interfaces</button>
    <span id="status" class="sub" style="margin:0"></span>
  </div>
  <div class="tools" style="margin-top:2px">
    <label style="font-size:12px;color:var(--muted)">Capture buffer
      <input type="number" id="bufMb" min="1" step="1" style="width:90px"> MB</label>
    <button id="bBuf" title="Total memory for stored packets (raw frames for the .pcap and the packet list). When it is full the oldest packets are rolled over to make room for new ones.">Apply</button>
    <span id="bufInfo" class="sub" style="margin:0;font-size:12px"></span>
  </div>
  <div id="pcapInfo" class="sub" style="margin:0;font-size:12px"></div>
  <div id="mcBox" class="mcbox" style="display:none">
    <div class="tools" style="margin:0 0 6px"><b style="font-size:13px">Multicast membership (IGMP)</b>
      <button id="bRejoin" title="Leave and join the PTP groups again so this computer sends fresh IGMP join reports">Re-join groups now</button>
      <label style="font-size:12px"><input type="checkbox" id="mcKeep"> Keep joins alive when no IGMP querier is seen (re-join every 60 s)</label></div>
    <div class="tw"><table><thead><tr><th>Interface</th><th>Joined (per the OS)</th><th>Join report seen on the wire</th>
      <th>IGMP querier on the network</th><th>OS IGMP version</th><th class="num">PTP packets</th><th>Re-joins</th></tr></thead>
      <tbody id="mcBody"></tbody></table></div>
    <div id="mcHints" class="mchints"></div>
  </div>
  <div id="msg" class="msg"></div><div id="err" class="msg"></div>
</div>

<div class="kpis">
  <div class="kpi"><b id="kTotal">0</b><span>PTP messages captured</span></div>
  <div class="kpi"><b id="kRate">0</b><span>messages / sec (5 s avg)</span></div>
  <div class="kpi"><b id="kBytes">0 B</b><span>total throughput received (frame bytes)</span></div>
  <div class="kpi"><b id="kBps">0 bps</b><span>current bandwidth per second (5 s avg)</span></div>
  <div class="kpi"><b id="kHosts">0</b><span>hosts sending Sync</span></div>
  <div class="kpi"><b id="kUp">-</b><span>capture time</span></div>
</div>

<div class="row" style="margin-bottom:14px">
  <div class="card"><h2>Messages received per second (last 5 min)</h2><canvas id="cTotal"></canvas></div>
  <div class="card"><h2>Total by message type</h2><canvas id="cBars"></canvas></div>
</div>

<div class="card"><h2>Per-second rate by message type (all types)</h2>
  <div class="sub" style="margin:-4px 0 8px;font-size:12px">Click a message type to turn it on or off; only the types that are on are drawn.</div>
  <div class="legend" id="legend"></div><canvas id="cTypes"></canvas></div>

<div class="card"><h2>Each message type</h2><div class="grid" id="mini"></div></div>

<div class="card"><h2>Hosts sending Sync <button class="xall" data-sec="sync" data-x="0">Expand all</button><button class="xall" data-sec="sync" data-x="1">Collapse all</button></h2>
  <div class="tw"><table><thead><tr>
   <th>Host</th><th>Role</th><th>Clock identity / MAC</th><th>Domain</th><th>Ver</th><th>Interface</th><th>Dest</th>
   <th class="num">Announced interval</th><th class="num">Observed interval</th>
   <th class="num" title="1 / announced interval">Sync/s (from interval)</th>
   <th class="num" title="Measured over the last 5 s">Sync/s (measured)</th>
   <th class="num">Sync packets</th>
   <th class="num" title="All PTP messages from this host, measured over the last 5 s">Total msgs/s (measured)</th>
   <th class="num">All PTP packets</th><th>Last seen</th></tr></thead>
   <tbody id="syncBody"></tbody></table></div>
  <div id="syncEmpty" class="empty">No Sync messages seen yet.</div></div>

<div class="card"><h2>Announce messages &ndash; clocks ranked by the Best Master Clock Algorithm <button class="xall" data-sec="ann" data-x="0">Expand all</button><button class="xall" data-sec="ann" data-x="1">Collapse all</button></h2>
  <div class="sub" style="margin-bottom:10px">Every clock seen sending Announce, ranked within each domain with the IEEE 1588 data set comparison:
   priority1 &rarr; clock class &rarr; clock accuracy &rarr; offset scaled log variance &rarr; priority2 &rarr; grandmaster identity, then (same grandmaster)
   steps removed &rarr; sender identity. <b>Rank 1 is the current master</b>; the rows below it are its successors in order.
   Clocks silent for 3 announce intervals are shown as expired; alternate-master announces are not eligible.
   <b>Boundary clocks</b> (Announce sender is not the grandmaster it announces, steps removed &gt; 0) are left out: they only relay the true grandmaster.</div>
  <div class="tools"><label><input type="checkbox" id="aHideExp"> Hide expired clocks</label>
   <label title="Boundary clocks relay the grandmaster&rsquo;s identity and data set, so they are never grandmaster candidates and are left out of the ranking"><input type="checkbox" id="aShowBC"> Show boundary clocks (not ranked)</label></div>
  <div class="tw" style="max-height:520px"><table><thead><tr>
   <th class="num">Rank</th><th>Role</th><th>Sender</th><th>Sender clock identity (port) / MAC</th><th>Interface</th>
   <th>Grandmaster identity / MAC</th><th class="num">Priority1</th><th>Clock class</th><th>Clock accuracy</th>
   <th class="num">Variance</th><th class="num">Priority2</th><th class="num">Steps removed</th><th>Time source</th>
   <th class="num">UTC offset</th><th>Flags</th><th class="num">Announce interval</th><th class="num">Announces</th>
   <th>Last seen</th><th>Why it ranks below the clock above</th></tr></thead>
   <tbody id="annBody"></tbody></table></div>
  <div id="annEmpty" class="empty">No Announce messages seen yet.</div>
  <div class="events" id="annEvents"></div></div>

<div class="card" id="slaveCard">
  <h2>2. Participate in a PTP domain (optional)</h2>
  <div class="sub" style="margin-bottom:10px">Acts as a slave-only ordinary clock: follows the best Announce in the domain,
   sends a Delay_Req after Sync messages and measures the correction needed to match the master
   (correction = &minus;offset from master). Measurement only &ndash; this host&rsquo;s clock is never adjusted.
   Needs the capture running on the chosen interface (its packet timestamps are used).</div>
  <div class="form">
    <label>Domain number<input type="number" id="sDomain" min="0" max="127" value="0" style="width:90px"></label>
    <label>Interface<select id="sIface"></select></label>
    <label>Delay_Req rate<select id="sDreq">
      <option value="auto">Auto (master&rsquo;s requested rate)</option>
      <option value="sync">Every Sync message</option>
      <option value="-4">16 / s</option><option value="-3">8 / s</option><option value="-2">4 / s</option>
      <option value="-1">2 / s</option><option value="0">1 / s</option><option value="1">1 per 2 s</option>
      <option value="2">1 per 4 s</option></select></label>
    <label>Send Delay_Req<select id="sDest">
      <option value="mc">Multicast (group for domain)</option><option value="uc">Unicast to master</option></select></label>
    <label>TTL (1&ndash;255)<input type="number" id="sTtl" min="1" max="255" value="1" style="width:80px"
      title="IP time-to-live of the Delay_Req packets. 1 keeps them on the local subnet; raise it to cross routers."></label>
    <label>Local clock timescale<select id="sScale">
      <option value="utc">UTC (convert master TAI)</option><option value="tai">PTP / TAI (no conversion)</option></select></label>
    <label>Only follow master IP<input type="text" id="sForce" placeholder="any" style="width:130px"></label>
  </div>
  <div class="tools">
    <button id="bJoin" class="primary">Join domain</button>
    <button id="bLeave">Leave</button>
    <span id="sStatus" class="sub" style="margin:0"></span>
  </div>
  <div id="sMsg" class="msg"></div>

  <div id="sBody" style="display:none">
    <div id="sTime" class="gmtime"></div>
    <div class="kpis" id="sKpis"></div>
    <h3>Clock correction per measurement <span class="legend" style="margin-left:8px">
      <span><i style="background:var(--accent)"></i>correction</span>
      <span><i style="background:var(--warn)"></i>mean &plusmn; 2&sigma; (dashed)</span>
      <span><i style="background:var(--bad)"></i>outside 2&sigma;</span></span></h3>
    <canvas id="cCorr" class="tall"></canvas>
    <h3>Mean path delay per measurement</h3>
    <canvas id="cDelay"></canvas>
    <h3>Statistics (all samples since joining or clearing)</h3>
    <div class="tw sstats"><table><thead><tr><th></th><th class="num">Correction</th><th class="num">Path delay</th></tr></thead>
      <tbody id="sStats"></tbody></table></div>
    <div class="events" id="sEvents"></div>
  </div>
</div>

<div class="card"><h2>Captured packets (newest first)</h2>
  <div class="tools">
    <select id="fType"><option value="">All types</option></select>
    <input type="text" id="fText" placeholder="Filter by IP, clock id, interface...">
    <label><input type="checkbox" id="pause"> Pause list</label>
    <span class="sub" style="margin:0" id="pktInfo"></span>
  </div>
  <div class="tw"><table><thead><tr>
   <th class="num">#</th><th>Time</th><th>Iface</th><th>Source</th><th>Destination</th><th>Transport</th>
   <th class="num" title="Differentiated Services Code Point (IP header)">DSCP</th><th>Type</th><th>Domain</th><th class="num">Seq</th><th class="num">Log interval</th><th class="num">Len</th></tr></thead>
   <tbody id="pktBody"></tbody></table></div></div>

<div class="card"><h2>Delay_Req interval check &ndash; hosts not matching their grandmaster&rsquo;s Sync interval</h2>
  <div class="sub">Each host&rsquo;s real Delay_Req interval is measured from arrival times (median of the last 128 gaps, at least 10 needed)
   and compared with the Sync interval of the grandmaster of the same domain (best Announce clock). A host is flagged when its interval is more than
   about 30 % off. The Delay_Req header interval field is 127 (0x7F) in the standard, which is not treated as a mismatch &ndash; only a
   header value other than 127 that differs from the Sync interval is reported.</div>
  <div class="tools"><label><input type="checkbox" id="dqAll"> Also show hosts that match / are still being measured</label>
   <button id="bDqCsv" title="Download the table as shown (respects the checkbox) as a .csv file">Download CSV</button>
   <span id="dqInfo" class="sub" style="margin:0"></span></div>
  <div class="tw"><table><thead><tr>
   <th>Host</th><th>Clock identity / MAC</th><th>Domain</th><th class="num">Delay_Req seen</th>
   <th class="num">Observed interval</th><th class="num">Delay_Req/s</th><th>Header interval field</th>
   <th>Domain GM (Sync from)</th><th class="num">GM Sync interval</th><th class="num">GM-requested interval (Delay_Resp)</th>
   <th class="num">Observed / Sync</th><th>Status</th><th>Detail</th></tr></thead>
   <tbody id="dqBody"></tbody></table></div></div>

<div class="card"><h2>Clock hierarchy &ndash; who is clocking off whom, per domain <button class="xall" data-sec="topo" data-x="0">Expand all</button><button class="xall" data-sec="topo" data-x="1">Collapse all</button></h2>
  <div class="sub">Every PTP device seen, grouped by domain and drawn as a tree under the clock it follows. The link is taken, in order of confidence, from
   <b>Delay_Resp</b> (the master names the port it answers), from <b>Announce</b> (the grandmaster itself, or a boundary clock one step further from the same grandmaster),
   from a <b>unicast Delay_Req</b> destination, or otherwise assumed to be the domain&rsquo;s current best master (marked <i>inferred</i>).
   Only traffic that reaches this interface is visible, so masters on other segments show as &ldquo;upstream not visible&rdquo;.</div>
  <div class="tools"><span class="srch"><input type="search" id="topoQ" placeholder="Search IP address, clock identity or MAC&hellip;"
     title="Matches any part of an IP address, clock identity or MAC. Separators are ignored for clock identities and MACs, so 00-1B-19-00-00-01, 001b.1900.0001 and 00:1b:19 all work. Esc clears."></span>
   <span id="topoQInfo" class="sub" style="margin:0;font-size:12px"></span></div>
  <div class="tw" style="max-height:640px"><table><thead><tr>
   <th>Device</th><th>Clock identity</th><th title="Derived from the clock identity (aa:bb:cc:FF:FE:dd:ee:ff &rarr; aa:bb:cc:dd:ee:ff)">MAC (from clock identity)</th>
   <th>Role</th><th>Clocking off</th><th>Clocking off (clock identity / MAC)</th>
   <th>Determined from</th><th>Grandmaster</th><th class="num">Steps removed</th><th class="num">Followers</th>
   <th>Sends</th><th>Last seen</th></tr></thead>
   <tbody id="topoBody"></tbody></table></div>
  <div id="topoEmpty" class="empty">No PTP devices seen yet.</div></div>
</main>
<script>
const WIN=300;
const TYPES=["Announce","Sync","Follow_Up","Delay_Req","Delay_Resp","Pdelay_Req","Pdelay_Resp","Pdelay_Resp_Follow_Up","Signaling","Management"];
const PAL=["#378ADD","#1D9E75","#7F77DD","#D85A30","#BA7517","#D4537E","#639922","#888780","#E24B4A","#0F6E56"];
const color=t=>{const i=TYPES.indexOf(t);return PAL[i<0?7:i]};
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
// MAC address inside a clock identity: aa:bb:cc:ff:fe:dd:ee:ff -> aa:bb:cc:dd:ee:ff (IEEE 1588 EUI-48 mapping)
const clockMac=c=>{const b=String(c||'').toLowerCase().split(':');return b.length===8&&b[3]==='ff'&&b[4]==='fe'?b.slice(0,3).concat(b.slice(5)).join(':'):null};
const NOMAC='This clock identity is not in the MAC-based form (xx:xx:xx:ff:fe:xx:xx:xx), so no MAC address can be derived from it';
const macSub=c=>{const m=clockMac(c);return m?`<br><small class="mac" title="MAC address derived from the clock identity">MAC ${m}</small>`:`<br><small title="${NOMAC}">MAC &ndash;</small>`};
let running=false,slRunning=false,sIfaceTouched=false;

async function api(path,body){
  const o=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)};
  const r=await fetch(path,o);return r.json();
}
const fmtLog=l=>{if(l===null||l===undefined)return '-';const s=Math.pow(2,l);
  return (s>=1?(+s.toPrecision(3))+' s':(+(s*1000).toPrecision(3))+' ms')+' (2^'+l+')'};
const fmtMs=ms=>ms===null?'-':(ms>=1000?(ms/1000).toFixed(2)+' s':ms.toFixed(1)+' ms');
const fmtRate=r=>(r===null||r===undefined)?'-':String(+r.toPrecision(3));
const fmtN=v=>v>=1000?(v/1000)+'k':(Number.isInteger(v)?v:v.toFixed(1));
const fmtDur=n=>n>=60?Math.round(n/60)+'m':n+'s';
const fmtUp=s=>{s=Math.floor(s);const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h?h+'h '+m+'m':m?m+'m '+(s%60)+'s':s+'s'};
const fmtScaled=(v,units,step)=>{let i=0;while(v>=step&&i<units.length-1){v/=step;i++}
  return (v>=100||i===0&&Number.isInteger(v)?v.toFixed(0):v>=10?v.toFixed(1):v.toFixed(2))+' '+units[i]};
const fmtBytes=v=>fmtScaled(v,['B','kB','MB','GB','TB'],1000);
const fmtBps=v=>fmtScaled(v,['bps','kbps','Mbps','Gbps'],1000);
let lastS=null,lastLegend='';
const selOff=new Set();                          // message types switched off in the per-second chart
function renderLegend(s){
  const html='<button class="lgx" data-all="1">All</button><button class="lgx" data-all="0">None</button>'+
    s.types.filter(t=>s.type_counts[t]).map(t=>`<button class="lg${selOff.has(t)?' off':''}" data-t="${esc(t)}" aria-pressed="${!selOff.has(t)}"><i style="background:${color(t)}"></i>${esc(t)}</button>`).join('');
  if(html!==lastLegend){$('legend').innerHTML=html;lastLegend=html}
}
function renderTypesChart(s){
  const sel=s.types.filter(t=>s.type_counts[t]&&!selOff.has(t)),c=$('cTypes');
  if(sel.length)return lineChart(c,sel.map(t=>({data:s.series[t],color:color(t)})));
  const r=devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;if(!w||!h)return;
  c.width=w*r;c.height=h*r;const g=c.getContext('2d');g.setTransform(r,0,0,r,0,0);
  g.fillStyle=css('--muted');g.font='13px system-ui,sans-serif';g.textAlign='center';g.textBaseline='middle';
  g.fillText(s.total?'No message type selected – click a type above to show it':'No messages captured yet',w/2,h/2);
}
$('legend').onclick=e=>{
  const b=e.target.closest('button');if(!b||!lastS)return;
  if(b.dataset.all==='1')selOff.clear();
  else if(b.dataset.all==='0')lastS.types.forEach(t=>selOff.add(t));
  else if(b.dataset.t){selOff.has(b.dataset.t)?selOff.delete(b.dataset.t):selOff.add(b.dataset.t)}
  renderLegend(lastS);renderTypesChart(lastS);
};
const nice=m=>{const p=Math.pow(10,Math.floor(Math.log10(m))),f=m/p;return (f<=1?1:f<=2?2:f<=5?5:10)*p};
const fmtNs=(v,d)=>{if(v===null||v===undefined||isNaN(v))return '-';const x=Math.abs(v);d=d===undefined?2:d;
  if(x>=1e9)return (v/1e9).toFixed(d)+' s';if(x>=1e6)return (v/1e6).toFixed(d)+' ms';
  if(x>=1e3)return (v/1e3).toFixed(d)+' µs';return v.toFixed(x<100?1:0)+' ns'};

function lineChart(c,series,o={}){
  const r=devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;if(!w||!h)return;
  c.width=w*r;c.height=h*r;const g=c.getContext('2d');g.setTransform(r,0,0,r,0,0);
  const sm=!!o.small,L=sm?30:40,R=6,T=6,B=sm?14:18,n=series[0].data.length;
  let m=1;for(const s of series)for(const v of s.data)if(v>m)m=v;m=nice(m);
  const tx=css('--muted'),gr=css('--line');
  g.font=(sm?10:11)+'px system-ui,sans-serif';g.lineWidth=1;
  const X=i=>L+(w-L-R)*(n<2?0:i/(n-1)),Y=v=>T+(h-T-B)*(1-v/m);
  g.fillStyle=tx;g.strokeStyle=gr;g.textAlign='right';g.textBaseline='middle';
  for(let k=0;k<=2;k++){const v=m*k/2,y=Y(v);g.beginPath();g.moveTo(L,y);g.lineTo(w-R,y);g.stroke();g.fillText(fmtN(v),L-4,y)}
  g.textBaseline='top';g.textAlign='left';g.fillText('-'+fmtDur(n),L,h-B+3);
  g.textAlign='right';g.fillText('now',w-R,h-B+3);
  for(const s of series){
    g.beginPath();s.data.forEach((v,i)=>i?g.lineTo(X(i),Y(v)):g.moveTo(X(i),Y(v)));
    g.strokeStyle=s.color;g.lineWidth=1.5;g.stroke();
    if(o.fill){g.lineTo(X(n-1),Y(0));g.lineTo(X(0),Y(0));g.closePath();g.globalAlpha=.14;g.fillStyle=s.color;g.fill();g.globalAlpha=1}
  }
}
function barChart(c,items){
  const r=devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;if(!w||!h)return;
  c.width=w*r;c.height=h*r;const g=c.getContext('2d');g.setTransform(r,0,0,r,0,0);
  const L=150,R=60,rh=h/items.length;let m=1;items.forEach(i=>{if(i.value>m)m=i.value});
  g.font='12px system-ui,sans-serif';g.textBaseline='middle';
  items.forEach((it,k)=>{
    const y=k*rh+rh/2,bw=(w-L-R)*it.value/m;
    g.fillStyle=css('--muted');g.textAlign='right';g.fillText(it.label,L-8,y);
    g.fillStyle=it.color;g.fillRect(L,y-rh*0.3,Math.max(bw,it.value?2:0),rh*0.6);
    g.fillStyle=css('--text');g.textAlign='left';g.fillText(it.value.toLocaleString(),L+bw+6,y);
  });
}
// auto-ranged chart for signed values, with mean and +-2 sigma band
function devChart(c,vals,st,col){
  const r=devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;if(!w||!h)return;
  c.width=w*r;c.height=h*r;const g=c.getContext('2d');g.setTransform(r,0,0,r,0,0);
  g.font='11px system-ui,sans-serif';
  const n=vals.length;
  if(!n){g.fillStyle=css('--muted');g.textAlign='center';g.fillText('No measurements yet',w/2,h/2);return}
  const L=66,R=8,T=8,B=18;
  let lo=Math.min(...vals),hi=Math.max(...vals);
  if(st){lo=Math.min(lo,st.band_lo);hi=Math.max(hi,st.band_hi)}
  if(hi===lo){hi+=1;lo-=1}
  const pad=(hi-lo)*0.08;lo-=pad;hi+=pad;
  const X=i=>L+(w-L-R)*(n<2?0.5:i/(n-1)),Y=v=>T+(h-T-B)*(1-(v-lo)/(hi-lo));
  g.strokeStyle=css('--line');g.fillStyle=css('--muted');g.lineWidth=1;g.textAlign='right';g.textBaseline='middle';
  for(let k=0;k<=3;k++){const v=lo+(hi-lo)*k/3,y=Y(v);g.beginPath();g.moveTo(L,y);g.lineTo(w-R,y);g.stroke();g.fillText(fmtNs(v,1),L-4,y)}
  g.textBaseline='top';g.textAlign='left';g.fillText('-'+n+' samples',L,h-B+3);g.textAlign='right';g.fillText('now',w-R,h-B+3);
  if(st&&n>1){
    g.globalAlpha=.08;g.fillStyle=css('--warn');g.fillRect(L,Y(st.band_hi),w-L-R,Y(st.band_lo)-Y(st.band_hi));g.globalAlpha=1;
    g.strokeStyle=css('--warn');g.setLineDash([5,4]);
    for(const v of [st.band_lo,st.band_hi]){g.beginPath();g.moveTo(L,Y(v));g.lineTo(w-R,Y(v));g.stroke()}
    g.setLineDash([]);g.globalAlpha=.7;g.beginPath();g.moveTo(L,Y(st.mean));g.lineTo(w-R,Y(st.mean));g.stroke();g.globalAlpha=1;
  }
  g.beginPath();vals.forEach((v,i)=>i?g.lineTo(X(i),Y(v)):g.moveTo(X(i),Y(v)));
  g.strokeStyle=col;g.lineWidth=1.3;g.stroke();
  if(st){g.fillStyle=css('--bad');
    vals.forEach((v,i)=>{if(Math.abs(v-st.mean)>st.two_sigma&&st.sd>0){g.beginPath();g.arc(X(i),Y(v),2.6,0,6.3);g.fill()}})}
  else{g.fillStyle=col;vals.forEach((v,i)=>{g.beginPath();g.arc(X(i),Y(v),2,0,6.3);g.fill()})}
}

function ensureMini(t){
  if($('m_'+t))return;
  const d=document.createElement('div');d.className='mini';
  d.innerHTML=`<h3><span style="color:${color(t)}">${esc(t)}</span></h3><div class="mstats" id="ms_${esc(t)}"></div><canvas id="m_${esc(t)}"></canvas>`;
  $('mini').appendChild(d);
  const o=document.createElement('option');o.value=t;o.textContent=t;$('fType').appendChild(o);
}
TYPES.forEach(ensureMini);

// ---- collapsible per-domain groups (state remembered in this browser) ----
let COLLAPSED=new Set();
try{COLLAPSED=new Set(JSON.parse(localStorage.getItem('ptpCollapsed')||'[]'))}catch(e){}
const saveCollapsed=()=>{try{localStorage.setItem('ptpCollapsed',JSON.stringify([...COLLAPSED]))}catch(e){}};
const isClosed=(sec,dom)=>COLLAPSED.has(sec+':'+dom);
const dhRow=(sec,dom,cols,html)=>`<tr class="dh${isClosed(sec,dom)?' closed':''}" data-sec="${sec}" data-dom="${esc(dom)}" title="Click to show / hide this domain"><td colspan="${cols}"><span class="caret">&#9662;</span>${html}</td></tr>`;
const SEEN_DOMS={sync:new Set(),ann:new Set(),topo:new Set()};
function rerender(sec){
  if(sec==='ann'&&lastAnn)renderAnnounce(lastAnn);
  if(sec==='sync'&&lastS)renderSync(lastS);
  if(sec==='topo'&&lastS)renderTopo(lastS.topology||[]);
}
document.addEventListener('click',e=>{
  const tr=e.target.closest('tr.dh[data-sec]');
  if(tr){const k=tr.dataset.sec+':'+tr.dataset.dom;COLLAPSED.has(k)?COLLAPSED.delete(k):COLLAPSED.add(k);saveCollapsed();rerender(tr.dataset.sec);return}
  const tg=e.target.closest('.tg[data-node]');
  if(tg){const k=tg.dataset.node;COLLAPSED.has(k)?COLLAPSED.delete(k):COLLAPSED.add(k);saveCollapsed();rerender(k.startsWith('snode:')?'sync':'topo');return}
  const b=e.target.closest('button.xall');
  if(b){const sec=b.dataset.sec;SEEN_DOMS[sec].forEach(d=>{b.dataset.x==='1'?COLLAPSED.add(sec+':'+d):COLLAPSED.delete(sec+':'+d)});
    if(b.dataset.x==='0'){const pre=sec==='topo'?'tnode:':sec==='sync'?'snode:':null;
      if(pre)[...COLLAPSED].forEach(k=>{if(k.startsWith(pre))COLLAPSED.delete(k)})}
    saveCollapsed();rerender(sec)}
});
const domSort=(a,b)=>{const x=+a,y=+b;return isNaN(x)||isNaN(y)?String(a).localeCompare(String(b)):x-y};

let lastAnn=null;
function renderAnnounce(a){
  lastAnn=a;
  const hide=$('aHideExp').checked,showBC=$('aShowBC').checked;
  const rows=a.rows.filter(r=>!(hide&&(r.role==='expired'||(r.role==='boundary'&&r.expired)))&&(showBC||r.role!=='boundary'));
  $('annEmpty').style.display=rows.length?'none':'block';
  const nbc=a.rows.filter(r=>r.role==='boundary').length;
  $('annEmpty').textContent=!a.rows.length?'No Announce messages seen yet.':(nbc===a.rows.length?`Only boundary clocks seen (${nbc}) – tick “Show boundary clocks” to list them.`:'All clocks have expired.');
  let html='',cur=null;
  const ago=s=>s<1?'now':s<120?Math.floor(s)+' s ago':fmtUp(s)+' ago';
  const domsAll=[...new Set(a.rows.map(r=>r.domain))];
  const ordered=[];
  domsAll.forEach(d=>{ordered.push({_hdr:d});rows.filter(r=>r.domain===d).forEach(r=>ordered.push(r))});
  for(const o of ordered){
    if(o._hdr!==undefined){
      const r={domain:o._hdr};
      cur=r.domain;SEEN_DOMS.ann.add(String(cur));
      const mine=a.rows.filter(x=>x.domain===cur),m=mine.find(x=>x.role==='master'),live=mine.filter(x=>x.rank!==null).length;
      const bcs=mine.filter(x=>x.role==='boundary'),gms=mine.length-bcs.length;
      html+=dhRow('ann',cur,19,`Domain ${r.domain} <span class="dhx">&middot; current grandmaster: ${m?`<b>${esc(m.src)}</b> (${esc(m.gm)})`:(bcs.length?`<b>not on this segment</b> &ndash; reached via boundary clock${bcs.length===1?'':'s'}, grandmaster ${esc(bcs[0].gm)}`:'<b>none</b> (no live Announce messages)')} &middot; ${live} live grandmaster candidate${live===1?'':'s'}, ${gms} seen`+
        (bcs.length?` &middot; ${bcs.length} boundary clock${bcs.length===1?'':'s'} ${showBC?'not ranked':'hidden'}`:'')+`</span>`);
      continue;
    }
    const r=o;
    if(isClosed('ann',cur))continue;
    const cls=r.role==='master'?'m':(r.role==='expired'||r.role==='ineligible'||r.role==='boundary')?'x':'';
    const rank=r.role==='master'?`<span class="tag" style="background:var(--ok)">1</span>`:(r.rank===null?'-':r.rank);
    const role=r.role==='master'?'<b>Master</b>':r.role==='successor'?'Successor '+(r.rank-1):r.role==='ineligible'?'Not eligible':r.role==='boundary'?'<span class="role bc">Boundary clock</span>'+(r.expired?' <small>(expired)</small>':''):'Expired';
    html+=`<tr class="${cls}"><td class="num">${rank}</td><td>${role}</td><td class="mono">${esc(r.src)}</td>
      <td class="mono">${esc(r.clock)} <small>(${r.port})</small>${macSub(r.clock)}</td><td>${esc(r.ifaces.join(', '))}</td>
      <td class="mono">${esc(r.gm)}${macSub(r.gm)}</td><td class="num">${r.p1}</td>
      <td>${r.cls} <small>${esc(r.cls_name)}</small></td><td>0x${r.acc.toString(16).toUpperCase().padStart(2,'0')} <small>${esc(r.acc_name)}</small></td>
      <td class="num">0x${r.var.toString(16).toUpperCase().padStart(4,'0')}</td><td class="num">${r.p2}</td><td class="num">${r.steps}</td>
      <td>${esc(r.tsrc_name)} <small>(0x${r.tsrc.toString(16).toUpperCase().padStart(2,'0')})</small></td>
      <td class="num">${r.utc_off} s</td><td>${r.flags.map(f=>`<span class="chip" title="${esc(f[1])}">${esc(f[0])}</span>`).join('')}</td>
      <td class="num">${esc(fmtLog(r.log))}</td><td class="num">${r.count.toLocaleString()}</td><td>${ago(r.age)}</td>
      <td>${esc(r.reason)}</td></tr>`;
  }
  $('annBody').innerHTML=html;
  $('annEvents').innerHTML=(a.events||[]).map(e=>`<div>${new Date(e.t*1000).toLocaleTimeString([],{hour12:false})} &ndash; ${esc(e.text)}</div>`).join('');
}
$('aHideExp').onchange=()=>{if(lastAnn)renderAnnounce(lastAnn)};
$('aShowBC').onchange=()=>{if(lastAnn)renderAnnounce(lastAnn)};
const SSTATE={stopped:'Not participating',listening:'Joined – listening for Announce messages',
  waiting_sync:'Master selected – waiting for Sync',waiting_delay:'Sync received – waiting for Delay_Resp',measuring:'Measuring'};
function renderSlave(sl){
  slRunning=sl.running;
  $('bJoin').disabled=sl.running;$('bLeave').disabled=!sl.running;
  ['sDomain','sIface','sDreq','sDest','sTtl','sScale','sForce'].forEach(id=>$(id).disabled=sl.running);
  let st=SSTATE[sl.state]||sl.state;
  if(sl.running)st+='  |  domain '+sl.cfg.domain+' on '+sl.cfg.iface+' as '+sl.ours.clock;
  $('sStatus').textContent=st;
  $('sMsg').textContent=sl.error?('Last error: '+sl.error):'';
  const has=sl.running||sl.series.corr.length>0;
  $('sBody').style.display=has?'block':'none';
  if(!has)return;
  const gt=sl.gm_time;
  $('sTime').innerHTML=gt?`<b>Time given by the grandmaster</b> <small>(from ${esc(gt.ip)}, GM ${esc(gt.gm)}; last Sync ${gt.age.toFixed(1)} s ago, carried forward by the local clock)</small>
   <table><tr><td>UTC</td><td class="mono">${esc(gt.utc)}</td></tr><tr><td>TAI (PTP time)</td><td class="mono">${esc(gt.tai)}</td></tr></table>
   <small>UTC = TAI &minus; ${gt.utc_off} s (currentUtcOffset from Announce)${gt.ptp_ts?'':' &ndash; GM uses an arbitrary (non-PTP) timescale, so the value is not true TAI'}</small>`
   :'<b>Time given by the grandmaster</b> <small>&ndash; waiting for a Sync from the master</small>';
  const c=sl.counts||{},m=sl.master,L=sl.last;
  const k=(v,l,cls)=>`<div class="kpi ${cls||''}"><b>${v}</b><span>${l}</span></div>`;
  $('sKpis').innerHTML=
    k(m?esc(m.ip):'-','master'+(m?' (GM '+esc(m.gm)+', prio '+m.p1+'/'+m.p2+', class '+m.cls+')':''),'s')+
    k(L?fmtNs(L.corr):'-','latest correction')+
    k(L?fmtNs(L.delay):'-','latest path delay')+
    k(sl.stats&&sl.stats.corr?sl.stats.corr.n.toLocaleString():'0','measurements')+
    k((c.dreq_tx||0).toLocaleString()+' / '+(c.dresp_rx||0).toLocaleString(),'Delay_Req sent / Delay_Resp received')+
    k((c.sync||0).toLocaleString(),'Sync from master'+((c.dreq_timeout||0)?' ('+c.dreq_timeout+' Delay_Req timed out)':''));
  const sc=sl.stats&&sl.stats.corr,sd=sl.stats&&sl.stats.delay;
  devChart($('cCorr'),sl.series.corr,sc,css('--accent'));
  devChart($('cDelay'),sl.series.delay,sd,css('--ok'));
  const row=(label,a,b,f)=>`<tr><td>${label}</td><td class="num">${a?f(a):'-'}</td><td class="num">${b?f(b):'-'}</td></tr>`;
  const ns=key=>x=>fmtNs(x[key]);
  $('sStats').innerHTML=
    row('Max',sc,sd,ns('max'))+row('Min',sc,sd,ns('min'))+row('Average',sc,sd,ns('mean'))+row('Median',sc,sd,ns('median'))+
    row('Standard deviation (1σ)',sc,sd,ns('sd'))+
    row('2nd standard deviation (2σ = 2 × σ)',sc,sd,ns('two_sigma'))+
    row('Outside mean ± 2σ – count',sc,sd,x=>x.exceed.toLocaleString())+
    row('Outside mean ± 2σ – % of total',sc,sd,x=>x.exceed_pct.toFixed(2)+' %')+
    row('Total measurements',sc,sd,x=>x.n.toLocaleString());
  $('sEvents').innerHTML=(sl.events||[]).map(e=>`<div>${new Date(e.t*1000).toLocaleTimeString([],{hour12:false})} &ndash; ${esc(e.text)}</div>`).join('');
}

function render(s){
  running=s.running;
  $('kTotal').textContent=s.total.toLocaleString();
  $('kRate').textContent=s.rate.toFixed(1);
  $('kBytes').textContent=fmtBytes(s.total_bytes);
  $('kBps').textContent=fmtBps(s.bps);
  $('kHosts').textContent=s.sync_hosts.length;
  $('kUp').textContent=s.running?fmtUp(s.uptime):'-';
  $('status').textContent=s.running?('Capturing on: '+s.active.join(', ')+'  |  filter: '+s.bpf):'Stopped';
  applyRunning();
  s.types.forEach(ensureMini);
  lineChart($('cTotal'),[{data:s.series._total,color:'#378ADD'}],{fill:true});
  barChart($('cBars'),s.types.slice(0,12).map(t=>({label:t,value:s.type_counts[t],color:color(t)})));
  lastS=s;renderLegend(s);renderTypesChart(s);renderDreq(s.dreq_hosts||[]);
  s.types.forEach(t=>{
    const q=s.type_stats[t]||{},pos=v=>v>0;      // values at 0 are not shown
    $('ms_'+t).innerHTML=
      (pos(q.total)?`<span>Total <b>${q.total.toLocaleString()}</b></span>`:'')+
      (pos(q.rate)?`<span>Now <b>${fmtRate(q.rate)}/s</b></span>`:'')+
      (pos(q.min)?`<span>Min <b>${fmtRate(q.min)}/s</b></span>`:'')+
      (pos(q.max)?`<span>Max <b>${fmtRate(q.max)}/s</b></span>`:'')+
      (pos(q.avg)?`<span>Avg <b>${fmtRate(q.avg)}/s</b></span>`:'');
    lineChart($('m_'+t),[{data:s.series[t],color:color(t)}],{small:true,fill:true});
  });
  renderSync(s);
  if(s.pcap){const p=s.pcap;$('bPcap').disabled=!p.packets;
    $('pcapInfo').textContent=p.packets?`${p.packets.toLocaleString()} packets (${fmtBytes(p.bytes)}) ready to download as .pcap`+
      (p.dropped?` – ${p.dropped.toLocaleString()} older packets rolled over (buffer full)`:'')+
      (p.skipped?` – ${p.skipped.toLocaleString()} non-Ethernet packets not included`:''):''}
  if(s.buffer)renderBuffer(s.buffer);
  if(s.announce)renderAnnounce(s.announce);
  if(s.slave)renderSlave(s.slave);
  renderTopo(s.topology||[]);
  renderMcast(s.mcast);
}

let mcKeepTouched=false;
function renderMcast(mc){
  const box=$('mcBox');
  if(!mc||!mc.ifaces||!mc.ifaces.length){box.style.display='none';return}
  box.style.display='block';
  if(!mcKeepTouched)$('mcKeep').checked=mc.keepalive;
  $('mcKeep').disabled=!mc.igmp_in_filter;
  const ago=s=>s==null?'-':s<1?'now':s<120?Math.floor(s)+' s ago':fmtUp(s)+' ago';
  const short=g=>'.'+g.split('.').pop();
  $('mcBody').innerHTML=mc.ifaces.map(f=>{
    const os=f.groups.map(g=>{const c=g.os===true?'y':g.os===false?'n':'u';
      return `<span class="gchip ${c}" title="${esc(g.group)}${g.os===null?' – the OS membership table could not be read':''}">${g.os===true?'&#10003;':g.os===false?'&#10007;':'?'} ${short(g.group)}</span>`}).join('');
    const rep=f.groups.map(g=>{const c=g.report_action==='join'?'y':g.report_action?'n':'u';
      return `<span class="gchip ${c}" title="${esc(g.group)}${g.report_age!=null?' – '+esc(g.report_action)+' (IGMPv'+g.report_version+') '+ago(g.report_age):' – not seen'}${g.others?' – '+g.others+' other device(s) joined it':''}">${short(g.group)} ${g.report_age!=null?ago(g.report_age):'not seen'}</span>`}).join('');
    const q=f.querier?`<b>${esc(f.querier.ip)}</b> <small>IGMPv${f.querier.version}, last query ${ago(f.querier.age)}</small>`:
      (mc.igmp_in_filter?`<span class="${f.uptime>=130?'warn':''}">none seen</span> <small>(${Math.floor(f.uptime)} s)</small>`:'<small>IGMP not in filter</small>');
    return `<tr><td class="mono">${esc(f.name)}<br><small>${f.ip?esc(f.ip):'no IPv4'}</small></td><td>${f.error?`<span class="bad">${esc(f.error)}</span>`:os}${!f.os_known&&!f.error?' <small>(OS table unavailable)</small>':''}</td>
      <td>${rep}</td><td>${q}</td><td>${f.os_version?'IGMPv'+f.os_version:'-'}</td>
      <td class="num">${f.ptp.toLocaleString()}${f.last_ptp_age!=null?`<br><small>${ago(f.last_ptp_age)}</small>`:''}</td>
      <td>${f.rejoins?f.rejoins+(f.auto_rejoins?` <small>(${f.auto_rejoins} automatic)</small>`:'')+`<br><small>last ${ago(f.last_rejoin_age)}</small>`:'-'}</td></tr>`}).join('');
  $('mcHints').innerHTML=mc.ifaces.map(f=>f.hints.map(h=>`<div class="${h[0]}"><b>${esc(f.name)}:</b> ${esc(h[1])}</div>`).join('')).join('');
}
$('mcKeep').onchange=async()=>{mcKeepTouched=true;await api('/api/igmp_keepalive',{on:$('mcKeep').checked});mcKeepTouched=false;tick()};
$('bRejoin').onclick=async()=>{
  $('bRejoin').disabled=true;
  const r=await api('/api/rejoin',{});
  $('bRejoin').disabled=false;
  $('msg').textContent=r.ok?'':(r.error||(r.results||[]).filter(x=>!x.ok).map(x=>x.iface+': '+x.error).join('\n')||'Re-join failed');
  tick();
};

function renderSync(s){
  const rowHtml=h=>{
    let cls=' class="num"';
    if(h.log!==null&&h.observed_ms!==null&&Math.abs(h.observed_ms/(Math.pow(2,h.log)*1000)-1)>.25)cls=' class="num warn" title="Observed interval differs from announced interval by more than 25%"';
    let rcls=' class="num"';
    if(h.announced_rate!==null&&Math.abs(h.sync_rate/h.announced_rate-1)>.25&&h.sync_count>5)rcls=' class="num warn" title="Measured Sync rate differs from the announced rate by more than 25%"';
    const ago=Math.max(0,s.now-h.last);
    const t=h._topo,dep=h._depth||0;
    const tg=h._subs?`<span class="tg${h._closed?' c':''}" data-node="${esc(h._key)}" title="Show / hide the boundary clocks under this one">&#9662;</span>`:'<span class="tg"></span>';
    const ind=(dep?`<i style="width:${(dep-1)*18}px"></i><i>&#9492;&#9472;&nbsp;</i>`:'')+tg;
    const role=t?`<span class="role ${ROLE_CLS[t.role]||''}">${esc(t.role)}</span>`+
      (t.role==='Boundary clock'?` <small>under ${esc(t.parent_ip||t.parent_clock||('GM '+(t.gm||'?')))}</small>`:''):'-';
    return `<tr${t&&t.role==='Boundary clock'?' class="bcrow"':''}><td class="mono tree">${ind}${esc(h.src)}</td><td class="tree">${role}</td><td class="mono">${esc(h.clock)}${macSub(h.clock)}</td><td>${esc(h.domain)}</td><td>v${h.version}</td>
      <td>${esc(h.ifaces.join(', '))}</td><td class="mono">${esc(h.dst.join(', '))}</td>
      <td class="num">${esc(fmtLog(h.log))}</td><td${cls}>${esc(fmtMs(h.observed_ms))}</td>
      <td class="num">${fmtRate(h.announced_rate)}</td><td${rcls}>${fmtRate(h.sync_rate)}</td>
      <td class="num"><b>${h.sync_count.toLocaleString()}</b></td>
      <td class="num">${fmtRate(h.total_rate)}</td><td class="num">${h.total_count.toLocaleString()}</td>
      <td>${ago<1?'now':ago<120?Math.floor(ago)+' s ago':fmtUp(ago)+' ago'}</td></tr>`};
  const groups={};
  s.sync_hosts.forEach(h=>{(groups[h.domain]=groups[h.domain]||[]).push(h)});
  const masters={};
  ((s.announce&&s.announce.rows)||[]).forEach(r=>{if(r.role==='master')masters[String(r.domain)]=r});
  let body='';
  const topo={};
  (s.topology||[]).forEach(td=>{topo[String(td.domain)]=td});
  Object.keys(groups).sort(domSort).forEach(d=>{
    SEEN_DOMS.sync.add(String(d));
    const m=masters[String(d)],td=topo[String(d)];
    let hs=groups[d];
    if(td){   // order like the clock hierarchy: GM first, its boundary clocks under it
      const idx={},byc={};
      td.rows.forEach((r,i)=>{idx[r.clock]=i;byc[r.clock]=r});
      hs=hs.slice().sort((a,b)=>(idx[a.clock]??1e9)-(idx[b.clock]??1e9));
      const inList=new Set(hs.map(h=>h.clock));
      hs.forEach(h=>{
        h._topo=byc[h.clock];let dep=0,p=h._topo&&h._topo.parent_clock,g=0;
        while(p&&g++<32){if(inList.has(p))dep++;p=byc[p]&&byc[p].parent_clock}
        if(!dep&&h._topo&&h._topo.role==='Boundary clock')dep=1;   // its GM is not sending Sync here
        h._depth=dep});
    }
    const rate=hs.reduce((a,h)=>a+(h.sync_rate||0),0),tot=hs.reduce((a,h)=>a+h.sync_count,0);
    const nbc=hs.filter(h=>h._topo&&h._topo.role==='Boundary clock').length;
    body+=dhRow('sync',d,15,`Domain ${esc(d)} <span class="dhx">&middot; ${hs.length} host${hs.length===1?'':'s'} sending Sync`+
      (nbc?` (${nbc} boundary clock${nbc===1?'':'s'})`:'')+` &middot; ${fmtRate(rate)} Sync/s, ${tot.toLocaleString()} total`+
      (m?` &middot; grandmaster <b>${esc(m.src)}</b> (${esc(m.gm)})`:(td&&td.gm?` &middot; grandmaster ${esc(td.gm)} <b>not on this segment</b>`:''))+`</span>`);
    if(!isClosed('sync',d)){
      let skip=null;
      hs.forEach((h,i)=>{
        h._depth=h._depth||0;h._key='snode:'+d+':'+h.clock;h._subs=0;
        for(let j=i+1;j<hs.length&&(hs[j]._depth||0)>h._depth;j++)h._subs++;
        h._closed=!!h._subs&&COLLAPSED.has(h._key);
      });
      hs.forEach(h=>{
        if(skip!==null){if(h._depth>skip)return;skip=null}
        body+=rowHtml(h);
        if(h._closed){skip=h._depth;
          body+=`<tr class="hid"><td colspan="15"><small>${'&nbsp;'.repeat(4+h._depth*5)}${h._subs} boundary clock${h._subs===1?'':'s'} under ${esc(h.src)} hidden &ndash; click &#9656; to show</small></td></tr>`}
      });
    }
  });
  $('syncBody').innerHTML=body;
  $('syncEmpty').style.display=s.sync_hosts.length?'none':'block';
}

const ROLE_CLS={'Grandmaster':'gm','Boundary clock':'bc','Master':'ma','Slave':''};
function topoQuery(){
  const q=$('topoQ').value.trim().toLowerCase();
  if(!q)return null;
  // separator-free hex form for clock identities / MACs (not for IP-like text, so "10.0" doesn't match hex "100")
  const hexy=/^[0-9a-f:\-\s]+$/.test(q)||/^[0-9a-f]{4}(\.[0-9a-f]{0,4})+$/.test(q);
  const qn=hexy?q.replace(/[^0-9a-f]/g,''):'';
  return {q,qn:qn.length>=2?qn:''};
}
function topoMatch(r,Q){
  const raw=[...r.ips,r.clock,r.mac||''];
  if(raw.some(f=>f.toLowerCase().includes(Q.q)))return true;
  return !!Q.qn&&[r.clock,r.mac].some(f=>f&&f.replace(/[^0-9a-f]/gi,'').toLowerCase().includes(Q.qn));
}
function hl(text,Q){
  const t=String(text);
  if(!Q)return esc(t);
  const i=t.toLowerCase().indexOf(Q.q);
  return i<0?esc(t):esc(t.slice(0,i))+'<mark>'+esc(t.slice(i,i+Q.q.length))+'</mark>'+esc(t.slice(i+Q.q.length));
}
function renderTopo(doms){
  let html='',nHits=0,nDoms=0;
  const ago=s=>s==null?'-':s<1?'now':s<120?Math.floor(s)+' s ago':fmtUp(s)+' ago';
  const Q=topoQuery();
  doms.forEach(d=>{
    SEEN_DOMS.topo.add(String(d.domain));
    // when searching: show matching devices plus the clocks above them (their path to the grandmaster)
    let show=null,hits=null;
    if(Q){
      hits=new Set();show=new Set();
      d.rows.forEach((r,i)=>{
        if(!topoMatch(r,Q))return;
        hits.add(i);show.add(i);
        let dep=r.depth;
        for(let j=i-1;j>=0&&dep>0;j--)if(d.rows[j].depth<dep){show.add(j);dep=d.rows[j].depth}
      });
      if(!hits.size)return;
      nHits+=hits.size;nDoms++;
    }
    const c=d.counts||{},parts=[['Grandmaster','grandmaster'],['Boundary clock','boundary clock'],['Master','master'],['Slave','slave']]
      .filter(x=>c[x[0]]).map(x=>c[x[0]]+' '+x[1]+(c[x[0]]===1?'':'s'));
    html+=dhRow('topo',d.domain,12,`Domain ${esc(d.domain)} <span class="dhx">&middot; ${d.rows.length} device${d.rows.length===1?'':'s'}${parts.length?' ('+parts.join(', ')+')':''}`+
      (d.gm?` &middot; grandmaster <b>${esc(d.gm)}</b>`+(d.master_ip?` via ${esc(d.master_ip)}`:''):'')+
      (Q?` &middot; <b>${hits.size} match${hits.size===1?'':'es'}</b>`:'')+`</span>`);
    if(!Q&&isClosed('topo',d.domain))return;     // a search always shows its results
    let skipBelow=null;
    html+=d.rows.map((r,i)=>{
      if(Q&&!show.has(i))return '';
      if(!Q&&skipBelow!==null){if(r.depth>skipBelow)return '';skipBelow=null}
      const key='tnode:'+d.domain+':'+r.clock,closed=!Q&&COLLAPSED.has(key);
      let hidden=0;
      if(closed&&r.followers){skipBelow=r.depth;for(let j=i+1;j<d.rows.length&&d.rows[j].depth>r.depth;j++)hidden++}
      const tg=r.followers&&!Q?`<span class="tg${closed?' c':''}" data-node="${esc(key)}" title="Show / hide the devices clocking off this one">&#9662;</span>`:'<span class="tg"></span>';
      const ind=(r.depth?`<i style="width:${(r.depth-1)*18}px"></i><i>&#9492;&#9472;&nbsp;</i>`:'')+tg;
      const hit=Q&&hits.has(i),H=hit?Q:null;
      const ipTxt=r.ips.length?(H&&!r.ips[0].toLowerCase().includes(Q.q)?(r.ips.find(x=>x.toLowerCase().includes(Q.q))||r.ips[0]):r.ips[0]):null;
      const dev=(ipTxt?hl(ipTxt,H)+(r.ips.length>1?` <small>+${r.ips.length-1}</small>`:''):'<small>(IP not seen)</small>')+(r.me?' <small>(this monitor)</small>':'');
      const inf=/inferred|Ambiguous|not visible/.test(r.via);
      const cls=[r.ann_role==='expired'?'x':'',hit?'hit':''].filter(Boolean).join(' ');
      return `<tr${cls?` class="${cls}"`:''}><td class="mono tree" title="${esc(r.ips.join(', '))}">${ind}${dev}</td><td class="mono">${hl(r.clock,H)}</td>
        <td class="mono">${r.mac?`<span class="mac">${hl(r.mac,H)}</span>`:`<small title="${NOMAC}">&ndash;</small>`}</td>
        <td><span class="role ${ROLE_CLS[r.role]||''}">${esc(r.role)}</span>${r.ann_role==='expired'?' <small>(expired)</small>':''}</td>
        <td class="mono">${r.parent_clock?(r.parent_ip?esc(r.parent_ip):'<small>(IP not seen)</small>'):'-'}</td>
        <td class="mono">${r.parent_clock?esc(r.parent_clock)+macSub(r.parent_clock):'-'}</td>
        <td${inf?' class="warn"':''}>${esc(r.via)}</td><td class="mono">${r.gm?esc(r.gm):'-'}</td>
        <td class="num">${r.steps==null?'-':r.steps}</td><td class="num">${r.followers||'-'}${closed&&hidden?` <small>(${hidden} hidden)</small>`:''}</td>
        <td>${r.sends.map(x=>`<span class="chip">${esc(x)}</span>`).join('')}</td><td>${ago(r.age)}</td></tr>`}).join('');
  });
  $('topoBody').innerHTML=html;
  $('topoEmpty').style.display=doms.length&&(!Q||nHits)?'none':'block';
  $('topoEmpty').textContent=doms.length?'No device matches “'+$('topoQ').value.trim()+'”.':'No PTP devices seen yet.';
  $('topoQInfo').textContent=Q?(nHits?`${nHits} device${nHits===1?'':'s'} match in ${nDoms} domain${nDoms===1?'':'s'} – the clocks above each match are shown for context`:''):'';
}
$('topoQ').oninput=()=>{if(lastS)renderTopo(lastS.topology||[])};
$('topoQ').onkeydown=e=>{if(e.key==='Escape'){$('topoQ').value='';$('topoQ').oninput()}};
let bufTouched=false;
function renderBuffer(b){
  const mb=Math.round(b.limit/1048576);
  $('bufMb').max=b.max_mb;
  if(!bufTouched&&document.activeElement!==$('bufMb'))$('bufMb').value=mb;
  const pct=b.limit?Math.min(100,100*b.used/b.limit):0;
  let t=`${fmtBytes(b.used)} of ${mb} MB used (${pct.toFixed(0)} %)`;
  if(b.oldest)t+=' – holding packets since '+new Date(b.oldest*1000).toLocaleTimeString([],{hour12:false});
  const rolled=Math.max(b.rolled_frames,b.rolled_rows);
  if(rolled)t+=` – rolling over: ${rolled.toLocaleString()} oldest packets dropped to make room`;
  $('bufInfo').textContent=t;
  $('bufInfo').className='sub'+(pct>=99?' warn':'');
}
$('bufMb').oninput=()=>{bufTouched=true};
$('bBuf').onclick=async()=>{
  const r=await api('/api/buffer',{mb:Number($('bufMb').value)});
  $('msg').textContent=r.ok?'':(r.error||'Could not change the buffer size');
  if(r.ok){bufTouched=false;tick()}
};

const DSCP_NAMES={0:'CS0',8:'CS1',16:'CS2',24:'CS3',32:'CS4',40:'CS5',48:'CS6',56:'CS7',46:'EF',10:'AF11',12:'AF12',14:'AF13',18:'AF21',20:'AF22',22:'AF23',26:'AF31',28:'AF32',30:'AF33',34:'AF41',36:'AF42',38:'AF43'};
function fmtDscp(d){if(d===null||d===undefined)return '-';return d+(DSCP_NAMES[d]?' <small>('+DSCP_NAMES[d]+')</small>':'')}
const DQ_CLS={mismatch:'bad',ok:'ok',measuring:'warn',idle:'warn',unknown:'warn'};
const DQ_TXT={mismatch:'Mismatch',ok:'Matches',measuring:'Measuring',idle:'Idle',unknown:'No GM Sync'};
function renderDreq(list){
  const all=$('dqAll').checked,bad=list.filter(r=>r.status==='mismatch');
  const rows=all?list:bad;
  $('dqInfo').textContent=list.length?(bad.length+' of '+list.length+' Delay_Req sender'+(list.length===1?'':'s')+' differ from the GM Sync interval'):'no Delay_Req seen yet';
  $('dqBody').innerHTML=rows.length?rows.map(r=>`<tr><td class="mono">${esc(r.src)}</td><td class="mono">${esc(r.clock)}${macSub(r.clock)}</td><td>${esc(r.domain)}</td>
    <td class="num">${r.count.toLocaleString()}</td><td class="num">${r.observed_ms==null?'-':esc(fmtMs(r.observed_ms))}</td>
    <td class="num">${r.observed_rate==null?'-':r.observed_rate.toFixed(2)}</td>
    <td>${r.declared==null?'127 (standard)':esc(fmtLog(r.declared))}</td>
    <td class="mono">${r.gm?esc(r.gm):'-'}</td><td class="num">${esc(fmtLog(r.sync_log))}</td><td class="num">${esc(fmtLog(r.resp_log))}</td>
    <td class="num">${r.ratio==null?'-':r.ratio.toFixed(2)+'\u00d7'}</td>
    <td><span class="${DQ_CLS[r.status]}">${DQ_TXT[r.status]}</span></td><td>${esc(r.note)}</td></tr>`).join('')
    :`<tr><td colspan="13" class="empty">${list.length?'All Delay_Req senders match their grandmaster\u2019s Sync interval.':'No Delay_Req messages captured yet.'}</td></tr>`;
}
$('dqAll').onchange=()=>{if(lastS)renderDreq(lastS.dreq_hosts||[])};
$('bDqCsv').onclick=()=>{location.href='/api/dreq.csv'+($('dqAll').checked?'?all=1':'')};
async function loadPackets(){
  const p=await api('/api/packets?limit=200&type='+encodeURIComponent($('fType').value)+'&q='+encodeURIComponent($('fText').value));
  $('pktInfo').textContent='showing '+p.length+' most recent'+(p.length?'':' (none match)');
  $('pktBody').innerHTML=p.map(r=>{
    const d=new Date(r.ts*1000);
    const t=d.toLocaleTimeString([],{hour12:false})+'.'+String(d.getMilliseconds()).padStart(3,'0');
    return `<tr><td class="num">${r.n}</td><td class="mono">${t}</td><td>${esc(r.iface)}</td><td class="mono">${esc(r.src)}</td>
      <td class="mono">${esc(r.dst)}</td><td>${esc(r.transport)}</td>
      <td class="num">${fmtDscp(r.dscp)}</td>
      <td><span class="tag" style="background:${color(r.type)}">${esc(r.type)}</span></td>
      <td>${esc(r.domain)}</td><td class="num">${r.seq}</td><td class="num">${r.log===null?'-':esc(fmtLog(r.log))}</td><td class="num">${r.length}</td></tr>`}).join('');
}

function applyRunning(){
  $('bStart').disabled=running;$('bStop').disabled=!running;
  document.querySelectorAll('#ifaces input').forEach(i=>i.disabled=running);
}
async function loadIfaces(){
  const all=$('showAll').checked;
  $('ifHint').textContent=all?'Showing every interface, including Wi-Fi, cellular, VPN/tunnel, link-down and loopback ones (tagged).'
    :'Active wired interfaces only – Wi-Fi, cellular, VPN/tunnel and link-down interfaces are hidden.';
  const list=await api('/api/interfaces'+(all?'?all=1':''));
  const prev=new Set([...document.querySelectorAll('#ifaces input:checked')].map(i=>i.value));
  $('ifaces').innerHTML=list.length?list.map(i=>{
    const nm=i.label&&i.label!==i.name?`${esc(i.label)} <small>(${esc(i.name)})</small>`:esc(i.name);
    const ips=i.ips&&i.ips.length?'<span class="ipv4">'+esc(i.ips.join(', '))+'</span>':'<span class="noip">no IPv4 address</span>';
    return `<label class="if"><input type="checkbox" value="${esc(i.name)}" ${prev.has(i.name)||i.selected?'checked':''}>
    <span><b>${nm}</b> <small>${ips} &middot; <span class="macaddr">${esc(i.mac)}</span> &middot; ${esc(i.state)}</small>${i.hidden?` <span class="why">${esc(i.hidden)}</span>`:''}</span></label>`}).join(''):'<div class="empty">No active wired interfaces found. Connect a cable (link must be up) and press Refresh interfaces, or tick &ldquo;Show all interfaces&rdquo;.</div>';
  applyRunning();
  const ss=$('sIface'),cur=ss.value;
  ss.innerHTML=list.map(i=>`<option value="${esc(i.name)}">${esc(i.label||i.name)} (${esc(i.ip)})</option>`).join('');
  if(sIfaceTouched&&[...ss.options].some(o=>o.value===cur))ss.value=cur;
  else{const a=list.find(i=>i.selected);if(a)ss.value=a.name}
}
$('sIface').onchange=()=>{sIfaceTouched=true};
$('bRefresh').onclick=loadIfaces;
$('showAll').onchange=loadIfaces;
$('bStart').onclick=async()=>{
  const sel=[...document.querySelectorAll('#ifaces input:checked')].map(i=>i.value);
  const r=await api('/api/start',{interfaces:sel});
  $('msg').textContent=(r.errors||[]).join('\n');await loadIfaces();tick();
};
$('bStop').onclick=async()=>{await api('/api/stop',{});$('msg').textContent='';tick();loadIfaces()};
$('bClear').onclick=async()=>{await api('/api/clear',{});tick()};
$('bPcap').onclick=()=>{location.href='/api/pcap'};
$('bJoin').onclick=async()=>{
  const r=await api('/api/slave/start',{domain:+$('sDomain').value,iface:$('sIface').value,dreq:$('sDreq').value,
    unicast:$('sDest').value==='uc',ttl:+$('sTtl').value,timescale:$('sScale').value,force_master:$('sForce').value});
  $('sMsg').textContent=r.ok?'':(r.error||'Failed');tick();
};
$('bLeave').onclick=async()=>{await api('/api/slave/stop',{});tick()};
$('fType').onchange=$('fText').oninput=()=>loadPackets();
async function tick(){
  try{
    render(await api('/api/state?window='+WIN));
    if(!$('pause').checked)await loadPackets();
    $('err').textContent='';
  }catch(e){$('err').textContent='Lost connection to the monitor program.'}
}
// ---- colour theme: System (default) / Light / Dark, remembered in this browser ----
function themePref(){try{const t=localStorage.getItem('ptpTheme');return t==='light'||t==='dark'?t:'system'}catch(e){return 'system'}}
function applyTheme(t,save){
  const root=document.documentElement;
  if(t==='light'||t==='dark')root.dataset.theme=t;else delete root.dataset.theme;
  if(save){try{t==='system'?localStorage.removeItem('ptpTheme'):localStorage.setItem('ptpTheme',t)}catch(e){}}
  document.querySelectorAll('[data-theme-set]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.themeSet===t)));
  if(lastS)render(lastS);            // charts are canvas: redraw with the new colours
}
document.querySelectorAll('[data-theme-set]').forEach(b=>b.onclick=()=>applyTheme(b.dataset.themeSet,true));
try{matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(themePref()==='system'&&lastS)render(lastS)})}catch(e){}
applyTheme(themePref(),false);

loadIfaces().then(tick);setInterval(tick,1000);
addEventListener('resize',tick);
</script></body></html>
"""


def open_browser(url):
    """Open the UI in the desktop user's browser.  Under sudo the browser is
    started as the real (logged-in) user, not as root."""
    user = os.environ.get("SUDO_USER")
    as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        if as_root and user and user != "root" and shutil.which("sudo"):
            if sys.platform == "darwin":
                cmd = ["sudo", "-u", user, "open", url]
            elif shutil.which("xdg-open"):
                import pwd
                uid = pwd.getpwnam(user).pw_uid
                env = ["%s=%s" % (k, os.environ[k]) for k in
                       ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY") if os.environ.get(k)]
                env += ["XDG_RUNTIME_DIR=/run/user/%d" % uid,
                        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus" % uid]
                cmd = ["sudo", "-u", user, "env"] + env + ["xdg-open", url]
            else:
                cmd = None
            if cmd and subprocess.call(cmd, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=15) == 0:
                return
        import webbrowser
        if webbrowser.open(url, new=2):
            return
    except Exception:
        pass
    print("Could not open a browser automatically - open %s yourself." % url)


def main():
    global CAP
    ap = argparse.ArgumentParser(description="PTP multicast monitor")
    ap.add_argument("--host", default="127.0.0.1",
                    help="web UI bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=None,
                    help="web UI port (default 8080; if that is busy the next "
                         "free port is used automatically)")
    ap.add_argument("-i", "--interface", action="append", default=[],
                    help="start capturing on this interface immediately "
                         "(repeatable)")
    ap.add_argument("--bpf", default=DEFAULT_BPF,
                    help="capture filter (default: %(default)s)")
    ap.add_argument("--no-promisc", action="store_true",
                    help="do not put the interface in promiscuous mode")
    ap.add_argument("--buffer-mb", "--max-pcap-mb", dest="buffer_mb", type=int,
                    default=DEFAULT_BUFFER_MB, metavar="MB",
                    help="capture buffer size: memory for stored packets (raw frames "
                         "for the .pcap download and the packet list). When full, the "
                         "oldest packets roll over. Can also be changed in the page "
                         "(default %(default)s)")
    ap.add_argument("--max-packets", type=int, help=argparse.SUPPRESS)  # obsolete
    ap.add_argument("--no-igmp-keepalive", action="store_true",
                    help="do not re-send the IGMP joins every %d s when no IGMP "
                         "querier is seen on the network" % KEEPALIVE_EVERY)
    ap.add_argument("--no-browser", action="store_true",
                    help="do not open the web UI in a browser at start-up")
    ap.add_argument("--join-domain", type=int, metavar="N",
                    help="also join PTP domain N as a slave (uses the first -i "
                         "interface)")
    ap.add_argument("--ttl", type=int, default=1, metavar="N",
                    help="IP TTL (1-255) for Delay_Req packets sent when "
                         "joining a domain (default 1)")
    a = ap.parse_args()

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("WARNING: not running as root - packet capture and the IGMP "
              "join will probably fail.", file=sys.stderr)

    STATS.reset()
    MCAST.keepalive = not a.no_igmp_keepalive

    def mcast_loop():
        while True:
            time.sleep(5)
            try:
                MCAST.tick(CAP, CAP.igmp_in_filter)
            except Exception:
                pass
    threading.Thread(target=mcast_loop, daemon=True).start()
    r = BUFFER.set_mb(a.buffer_mb)
    if not r["ok"]:
        sys.exit("ERROR: --buffer-mb: " + r["error"])
    CAP = Capture(a.bpf, not a.no_promisc)
    if a.interface:
        res = CAP.start(a.interface)
        for e in res.get("errors", []):
            print("ERROR:", e, file=sys.stderr)
        if a.join_domain is not None and CAP.running:
            r = SLAVE.start_from_request(dict(domain=a.join_domain,
                                              iface=a.interface[0], ttl=a.ttl))
            if not r.get("ok"):
                print("ERROR:", r.get("error"), file=sys.stderr)

    explicit = a.port is not None            # an explicitly requested port is never changed
    port0 = a.port if explicit else 8080
    srv, port = None, port0
    for port in ([port0] if explicit else range(port0, port0 + 50)):
        try:
            srv = ThreadingHTTPServer((a.host, port), Handler)
            break
        except OSError as e:
            if e.errno not in (errno.EADDRINUSE, errno.EACCES):
                CAP.stop()
                raise
    if srv is None:
        CAP.stop()
        sys.exit("Port %d is already in use%s.\n"
                 "  Pick another one:       sudo python3 %s --port 9000\n"
                 "  Or see what is using it: sudo lsof -nP -iTCP:%d -sTCP:LISTEN\n"
                 "  (it may be an earlier copy of this program - stop it with Ctrl+C)"
                 % (port0, "" if explicit else " (and the next 49 ports)",
                    os.path.basename(sys.argv[0]), port0))
    if port != port0:
        print("Port %d is in use - using port %d instead." % (port0, port))
    view_host = a.host
    if view_host in ("", "0.0.0.0"):
        view_host = "127.0.0.1"
    elif view_host == "::":
        view_host = "[::1]"
    elif ":" in view_host and not view_host.startswith("["):
        view_host = "[%s]" % view_host
    url = "http://%s:%d" % (view_host, port)
    print("PTP Monitor UI: %s" % url)
    if not a.no_browser:
        threading.Timer(0.6, open_browser, args=(url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        CAP.stop()


if __name__ == "__main__":
    main()
