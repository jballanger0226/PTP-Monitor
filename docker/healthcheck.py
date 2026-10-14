#!/usr/bin/env python3
"""Container health check, by mode (PTP_MODE):
  standalone  the web UI answers /api/state
  collector   the HTTPS server answers /healthz
  node        the collector accepted a push recently (status file written by the node)"""
import os
import ssl
import sys
import time
import urllib.request as u

mode = os.environ.get("PTP_MODE", "standalone")
host = os.environ.get("PTP_HOST", "0.0.0.0")
host = "127.0.0.1" if host in ("", "0.0.0.0", "::") else host
try:
    if mode == "collector":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE            # talking to ourselves, self-signed is fine
        u.urlopen("https://%s:%s/healthz" % (host, os.environ.get("PTP_PORT", "8443")),
                  timeout=4, context=ctx)
    elif mode == "node":
        f = os.environ.get("PTP_NODE_STATUS_FILE", "/tmp/ptp_node_ok")
        interval = float(os.environ.get("PTP_PUSH_INTERVAL", "2"))
        if time.time() - os.stat(f).st_mtime > max(30, 5 * interval):
            sys.exit("no push accepted by the collector recently")
    else:
        u.urlopen("http://%s:%s/api/state" % (host, os.environ.get("PTP_PORT", "8080")), timeout=4)
except SystemExit:
    raise
except Exception as e:
    sys.exit(str(e))
