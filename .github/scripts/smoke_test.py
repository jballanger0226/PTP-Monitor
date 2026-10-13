#!/usr/bin/env python3
"""Smoke test for the container image, run by the CI workflow against a
container started from it (name "ptp", web UI on 127.0.0.1:8080).
Results are reported as GitHub annotations so they show on the pull request."""
import json
import struct
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8080"


def annotate(level, title, msg):
    msg = str(msg).replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print("::%s title=%s::%s" % (level, title, msg[:4000]), flush=True)


def get(path, raw=False, timeout=10):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        data = r.read()
    return data if raw else json.loads(data)


def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def fail(what, detail=""):
    logs = subprocess.run(["docker", "logs", "--tail", "40", "ptp"], capture_output=True, text=True)
    annotate("error", "Smoke test failed: " + what,
             "%s\n--- container log ---\n%s%s" % (detail, logs.stdout, logs.stderr))
    sys.exit(1)


def main():
    for _ in range(40):                                   # web UI up?
        try:
            get("/api/state")
            break
        except Exception as e:
            err = e
            time.sleep(1)
    else:
        fail("web UI did not come up", repr(err))

    if b"PTP Multicast Monitor" not in get("/", raw=True):
        fail("dashboard page", "title not found")

    ifs = get("/api/interfaces?all=1")
    annotate("notice", "Interfaces in the container",
             ", ".join("%s %s (%s)" % (i["name"], i["ip"], i["hidden"] or "shown") for i in ifs))

    r = post("/api/start", {"interfaces": ["eth0"]})
    if not r.get("ok"):
        fail("capture did not start on eth0", json.dumps(r))

    s, groups = None, []
    for _ in range(15):                                    # joined per the OS?
        time.sleep(1)
        s = get("/api/state")
        m = (s.get("mcast") or {}).get("ifaces") or []
        groups = m[0]["groups"] if m else []
        if s.get("running") and groups and all(g["os"] for g in groups):
            break
    else:
        fail("PTP multicast groups not joined", json.dumps((s or {}).get("mcast"), indent=1))
    m = s["mcast"]["ifaces"][0]
    annotate("notice", "Multicast membership on eth0",
             "joined per OS: %s\njoin reports seen: %s\nIGMP version: %s"
             % (", ".join(g["group"] for g in groups if g["os"]),
                ", ".join("%s (%s)" % (g["group"], g["report_action"]) for g in groups if g["report_action"]),
                m.get("os_version")))

    pcap = get("/api/pcap", raw=True)
    if len(pcap) < 24 or struct.unpack("<I", pcap[:4])[0] != 0xA1B2C3D4:
        fail("pcap download", "bad header: %r" % pcap[:24])
    annotate("notice", "pcap download", "%d bytes, %d packets in buffer"
             % (len(pcap), s["pcap"]["packets"]))

    v = subprocess.run(["docker", "exec", "ptp", "python", "-c",
                        "import scapy,sys; print('Python', sys.version.split()[0], '- scapy', scapy.VERSION)"],
                       capture_output=True, text=True)
    annotate("notice", "Image contents", v.stdout.strip() or v.stderr.strip())
    print("smoke test passed")


if __name__ == "__main__":
    main()
