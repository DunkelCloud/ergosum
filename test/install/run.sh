#!/usr/bin/env bash
# A new machine set up by deploy/install.sh, in containers of the
# distributions it supports: Debian (useradd, wget), Ubuntu 20.04 (systemd
# without /etc/sysusers.d, curl) and Alpine (BusyBox, OpenRC). Each
# downloads a release from a local web server, laid out as GitHub serves
# it and signed with a key made for the test (test/install/release.sh);
# test/install/machine.sh runs in the container and checks the result.
#
# Needs docker and ssh-keygen. BIN is a build of ergosumd with a release
# version (see .github/workflows/ci.yml).
# Usage: BIN=dist test/install/run.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d /tmp/ergosum-install.XXXXXX)
NET=ergosum-install-$$
# Pinned like the actions in CI; bump them deliberately.
IMAGES=(
	debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
	ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214
	alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
)
WEB=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec

log() { printf '\n== %s\n' "$*"; }

cleanup() {
	set +e
	docker rm -f "$NET-web" >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
	if [ "${KEEP:-}" = "" ]; then rm -rf "$W"; fi
}
trap cleanup EXIT

version=$("$BIN/ergosumd" version | awk '{print $2}')
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')

log "release $version, signed with a test key"
"$ROOT/test/install/release.sh" "$W" linux "$arch" "$BIN"

docker network create "$NET" >/dev/null
docker run -d --name "$NET-web" --network "$NET" -v "$W/www:/www:ro" "$WEB" \
	httpd -f -p 8000 -h /www >/dev/null

for image in "${IMAGES[@]}"; do
	log "${image%@*}"
	docker run --rm --network "$NET" --hostname host1.example.com \
		-v "$W/install.sh:/t/install.sh:ro" \
		-v "$ROOT/test/install/machine.sh:/t/machine.sh:ro" \
		-v "$W/release-signers:/t/release-signers:ro" \
		-v "$W/other-signers:/t/other-signers:ro" \
		-e URL="http://$NET-web:8000" -e RELEASE="$version" \
		"$image" sh /t/machine.sh
done

log "PASS"
