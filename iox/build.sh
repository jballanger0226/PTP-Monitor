#!/usr/bin/env bash
# Builds the Catalyst 9300/9300X node image and saves it as a tar for the switch.
#   iox/build.sh [version]        -> ptp-node-<version>.tar  (default version: dev)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-dev}"
docker buildx build --platform linux/amd64 -f Dockerfile.iox -t "ptp-node:${VERSION}" --load .
docker save "ptp-node:${VERSION}" -o "ptp-node-${VERSION}.tar"
ls -lh "ptp-node-${VERSION}.tar"
sha256sum "ptp-node-${VERSION}.tar" 2>/dev/null || shasum -a 256 "ptp-node-${VERSION}.tar"
echo "Next: copy it to the switch SSD (docs/CATALYST-9300.md)."
