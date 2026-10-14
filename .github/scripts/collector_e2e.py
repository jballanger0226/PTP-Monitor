#!/usr/bin/env python3
"""End-to-end test of the collector (--mode collector), standard library only.

Run against a collector started with a known first-admin password, e.g.

    PTP_ADMIN_PASSWORD=ci-admin-password-1 python3 ptp_monitor.py --mode collector \
        --data-dir /tmp/ptpdata --port 18443 --host 127.0.0.1 &
    COLLECTOR=https://127.0.0.1:18443 ADMIN_PASSWORD=ci-admin-password-1 \
        python3 .github/scripts/collector_e2e.py

It logs in, creates a viewer and a node, pushes a minimal state the way a node does,
reads it back, and checks that bad credentials, bad tokens, cross-origin posts and
the login throttle are refused.  The throttle check runs last and locks out this
client's address for ten minutes, so use a throw-away collector.
"""
import gzip
import http.client
import json
import os
import ssl
import sys
import time
from urllib.parse import urlparse

BASE = os.environ.get("COLLECTOR", "https://127.0.0.1:8443")
ADMIN_PW = os.environ.get("ADMIN_PASSWORD", "")
U = urlparse(BASE)
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE            # the collector's certificate is self-signed
FAILED = []


class Client:
    def __init__(self):
        self.cookie = None

    def req(self, method, path, body=None, headers=None, raw=None):
        h = dict(headers or {})
        if self.cookie:
            h["Cookie"] = self.cookie
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        c = http.client.HTTPSConnection(U.hostname, U.port or 443, context=CTX, timeout=15)
        try:
            c.request(method, path, data, h)
            r = c.getresponse()
            payload = r.read()
            for k, v in r.getheaders():
                if k.lower() == "set-cookie":
                    pair = v.split(";", 1)[0]
                    self.cookie = pair if not pair.endswith("=") else None
            try:
                js = json.loads(payload)
            except ValueError:
                js = None
            return r.status, js, payload, dict((k.lower(), v) for k, v in r.getheaders())
        finally:
            c.close()


def check(name, cond, detail=""):
    print(("ok    " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)))
    if not cond:
        FAILED.append(name)


def minimal_state():
    return dict(total=7, rate=1.5, bps=100.0, types=["Sync"], series={"_total": [0], "Sync": [0]},
                sync_hosts=[], dreq_hosts=[], running=True, active=["eth1"],
                announce=dict(rows=[], now=time.time(), events=[]), topology=[])


def push(token, state=None, extra=None, control=True):
    body = gzip.compress(json.dumps(dict(
        info=dict(proto=1, hostname="ci-node", platform="linux", interval=2.0, control=control),
        state=state or minimal_state(), packets=[
            dict(n=1, ts=time.time(), iface="eth1", src="10.0.0.1", dst="224.0.1.129",
                 transport="UDP/319", dscp=46, type="Sync", domain="0", seq=1, log=0,
                 length=90, clock="aa:bb:cc:ff:fe:00:00:01")], **(extra or {}))).encode())
    return Client().req("POST", "/api/node/push", raw=body, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json",
        "Content-Encoding": "gzip"} if token else {"Content-Type": "application/json"})


def main():
    if not ADMIN_PW:
        sys.exit("set ADMIN_PASSWORD (the first admin's password)")
    a = Client()
    st, _, body, _ = a.req("GET", "/healthz")
    check("healthz answers without login", st == 200 and body.strip() == b"ok", st)
    st, _, _, h = a.req("GET", "/")
    check("dashboard redirects to /login when logged out", st == 302 and h.get("location", "").endswith("/login"), (st, h))
    st, js, _, _ = a.req("GET", "/api/nodes")
    check("API refuses requests without a session", st == 401, st)
    st, js, _, _ = a.req("POST", "/api/login", dict(username="admin", password="not the password"))
    check("wrong password is refused", st == 401 and not js.get("ok"), (st, js))
    st, js, _, h = a.req("POST", "/api/login", dict(username="admin", password=ADMIN_PW))
    check("admin can log in", st == 200 and js.get("ok") and a.cookie, (st, js))
    st, _, _, h = a.req("GET", "/api/me")
    check("security headers present", "strict-transport-security" in h and h.get("x-frame-options") == "DENY"
          and "content-security-policy" in h, h)

    # nodes
    st, js, _, _ = a.req("POST", "/api/admin/nodes", dict(name="ci node"))
    check("invalid node name refused", st == 400, (st, js))
    st, js, _, _ = a.req("POST", "/api/admin/nodes", dict(name="ci-node"))
    token = (js or {}).get("token", "")
    check("admin can add a node and gets a token", st == 200 and token.startswith("ptpn_"), (st, js))
    st, _, _, _ = a.req("GET", "/node/ci-node")
    check("node page before any data is a placeholder (200)", st == 200, st)
    st, _, _, _ = a.req("GET", "/api/state?node=ci-node")
    check("no state before the first push (404)", st == 404, st)
    st, js, _, _ = push("ptpn_wrong")
    check("push with an unknown token is refused", st == 401, (st, js))
    st, js, _, _ = push(None)
    check("push without a token is refused", st == 401, (st, js))
    st, js, _, _ = push(token, extra=None, state=dict(minimal_state(), types="nope"))
    check("push with a malformed state is rejected", st == 400, (st, js))
    st, js, _, _ = push(token)
    check("push with the node's token is accepted", st == 200 and js.get("ok"), (st, js))
    st, js, _, _ = a.req("GET", "/api/state?node=ci-node")
    check("pushed state is served back", st == 200 and js["total"] == 7 and js["collector"]["online"], (st, js))
    st, js, _, _ = a.req("GET", "/api/nodes")
    row = next((n for n in js or [] if n["name"] == "ci-node"), None)
    check("node list shows the node online", bool(row and row["online"] and row["active"] == ["eth1"]), js)
    st, js, _, _ = a.req("GET", "/api/packets?node=ci-node&type=Sync")
    check("pushed packets are served", st == 200 and len(js) == 1, (st, js))
    st, _, body, _ = a.req("GET", "/node/ci-node")
    check("node dashboard is the standard page", st == 200 and b"PTP Multicast Monitor" in body and b'"ci-node"' in body, st)
    st, _, _, _ = a.req("POST", "/api/start", dict(interfaces=["eth0"]))
    check("capture controls do not exist on the collector", st == 404, st)

    # users and roles
    st, js, _, _ = a.req("POST", "/api/admin/users", dict(username="viewer1", password="short", role="viewer"))
    check("short password refused", st == 400, (st, js))
    st, js, _, _ = a.req("POST", "/api/admin/users", dict(username="viewer1", password="viewer-pass-1", role="viewer"))
    check("admin can add a viewer", st == 200 and js.get("ok"), (st, js))
    v = Client()
    st, js, _, _ = v.req("POST", "/api/login", dict(username="viewer1", password="viewer-pass-1"))
    check("new user can log in but must change the password", st == 200 and js.get("must_change"), (st, js))
    st, _, _, _ = v.req("GET", "/api/nodes")
    check("... and is blocked until they do", st == 403, st)
    st, js, _, _ = v.req("POST", "/api/account/password", dict(current="viewer-pass-1", new="viewer-pass-2"))
    check("password change works", st == 200 and js.get("ok"), (st, js))
    st, js, _, _ = v.req("GET", "/api/nodes")
    check("viewer can see nodes afterwards", st == 200, st)
    st, _, _, _ = v.req("GET", "/api/admin/users")
    check("viewer cannot list users", st == 403, st)
    st, _, _, _ = v.req("POST", "/api/admin/nodes", dict(name="evil"))
    check("viewer cannot add nodes", st == 403, st)
    st, _, _, _ = v.req("GET", "/admin")
    check("viewer cannot open the admin page", st == 403, st)

    # remote control: join / leave a PTP domain on a node
    def state_cmds():
        return a.req("GET", "/api/state?node=ci-node")[1]["collector"]["commands"]
    st, js, _, _ = v.req("POST", "/api/slave/start?node=ci-node", dict(domain=0, iface="eth1"))
    check("viewer cannot make a node join a domain", st == 403, (st, js))
    st, js, _, _ = a.req("POST", "/api/slave/start?node=ci-node", dict(domain=300, iface="eth1"))
    check("bad domain number refused", st == 400, (st, js))
    st, js, _, _ = a.req("POST", "/api/slave/start?node=ci-node", dict(domain=0, iface="eth9"))
    check("interface the node is not capturing on refused", st == 400 and "eth9" in js["error"], (st, js))
    st, js, _, _ = a.req("POST", "/api/slave/start?node=nope", dict(domain=0, iface="eth1"))
    check("unknown node refused", st == 404, (st, js))
    st, js, _, _ = a.req("POST", "/api/slave/start?node=ci-node", dict(domain=1, iface="eth1"))
    first = (js or {}).get("id")
    check("admin can queue a join", st == 200 and js.get("queued") and first, (st, js))
    st, js, _, _ = a.req("POST", "/api/slave/start?node=ci-node", dict(domain=2, iface="eth1", ttl=16, dreq="-3"))
    second = (js or {}).get("id")
    st, js, _, _ = push(token)
    cmds = (js or {}).get("commands", [])
    check("node gets only the newest join with the next push",
          len(cmds) == 1 and cmds[0]["id"] == second and cmds[0]["type"] == "slave_start"
          and cmds[0]["params"]["domain"] == 2 and cmds[0]["params"]["ttl"] == 16, (st, js))
    cs = {c["id"]: c for c in state_cmds()}
    check("the older join shows as superseded, the new one as sent",
          cs[first]["status"] == "superseded" and cs[second]["status"] == "sent", cs)
    st, js, _, _ = push(token)
    check("a command is delivered only once", (js or {}).get("commands") == [], js)
    st, js, _, _ = push(token, extra=dict(results=[dict(id=second, ok=False, error="eth1 has no IPv4 address")]))
    cs = {c["id"]: c for c in state_cmds()}
    check("a failure reported by the node is shown", cs[second]["status"] == "failed"
          and "IPv4" in cs[second]["error"], cs.get(second))
    st, js, _, _ = a.req("POST", "/api/slave/start?node=ci-node", dict(domain=0, iface="eth1"))
    third = js["id"]
    push(token)
    push(token, extra=dict(results=[dict(id=third, ok=True)]))
    check("success reported by the node is shown", {c["id"]: c for c in state_cmds()}[third]["status"] == "ok")
    st, js, _, _ = a.req("POST", "/api/slave/stop?node=ci-node", {})
    stop_id = js["id"]
    st, js, _, _ = push(token)
    check("leave command reaches the node", [c["type"] for c in js["commands"]] == ["slave_stop"], js)
    st, js, _, _ = push(token, control=False)
    st, js, _, _ = a.req("POST", "/api/slave/start?node=ci-node", dict(domain=0, iface="eth1"))
    check("node with remote control switched off cannot be told to join", st == 409, (st, js))
    push(token, control=True)

    # cross-origin and logout
    st, js, _, _ = a.req("POST", "/api/admin/nodes", dict(name="x-origin"), headers={"Origin": "https://evil.example"})
    check("cross-origin POST is refused", st == 403, (st, js))
    st, js, _, _ = a.req("POST", "/api/admin/nodes", dict(name="ci-node-2"), headers={"Origin": BASE})
    check("same-origin POST is accepted", st == 200, (st, js))
    st, js, _, _ = a.req("POST", "/api/admin/nodes/ci-node-2/rotate", {})
    new_token = (js or {}).get("token", "")
    st, js, _, _ = push(new_token)
    check("rotated token works", st == 200, (st, js))
    st, js, _, _ = a.req("POST", "/api/admin/nodes/ci-node-2/delete", {})
    st, js, _, _ = push(new_token)
    check("a removed node's token stops working", st == 401, (st, js))
    st, js, _, _ = a.req("POST", "/api/admin/users/admin/delete", {})
    check("cannot delete yourself", st == 400, (st, js))
    st, js, _, _ = a.req("POST", "/api/admin/users/viewer1/delete", {})
    check("admin can delete a user", st == 200, (st, js))
    st, _, _, _ = v.req("GET", "/api/nodes")
    check("deleted user's session is gone", st == 401, st)
    st, js, _, _ = a.req("POST", "/api/logout", {})
    st, _, _, _ = a.req("GET", "/api/nodes")
    check("logout ends the session", st == 401, st)

    # login throttle (last: it blocks this address for ten minutes)
    codes = [Client().req("POST", "/api/login", dict(username="nobody", password="x" * 12))[0]
             for _ in range(12)]
    check("repeated failed logins are throttled", 429 in codes, codes)
    st, js, _, h = Client().req("POST", "/api/login", dict(username="admin", password=ADMIN_PW))
    check("... even with the right password while throttled", st == 429 and "retry-after" in h, (st, js))

    print("\n%d check(s) failed" % len(FAILED) if FAILED else "\nall checks passed")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
