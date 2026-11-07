#!/usr/bin/env bash
# A new machine and a new authority host set up by deploy/install.sh, in
# containers of the distributions it supports: Debian (useradd, wget),
# Ubuntu 20.04 (systemd without /etc/sysusers.d, curl) and Alpine (BusyBox,
# OpenRC). Each downloads releases from a local web server, laid out as
# GitHub serves them and signed with a key made for the test
# (test/install/release.sh). In a container of each distribution
# test/install/machine.sh sets up and checks a machine; in another,
# test/install/authority.sh sets up an authority, runs it and updates it.
#
# Needs docker and ssh-keygen. BIN holds builds of ergosumd and ergosum
# with a release version, NEXT a newer build of ergosum (see
# .github/workflows/ci.yml).
# Usage: BIN=dist NEXT=dist-next test/install/run.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
NEXT=${NEXT:?set NEXT to a build of ergosum newer than BIN}
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
next=$("$NEXT/ergosum" version | awk 'NR == 1 {print $2}')
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')

log "releases $version and $next, signed with a test key"
# $version is the latest, so that the runs without --version stay with it;
# the authority's update names $next.
"$ROOT/test/install/release.sh" "$W" linux "$arch" "$NEXT" "$BIN"

docker network create "$NET" >/dev/null
docker run -d --name "$NET-web" --network "$NET" -v "$W/www:/www:ro" "$WEB" \
	httpd -f -p 8000 -h /www >/dev/null

for image in "${IMAGES[@]}"; do
	for t in machine authority; do
		log "${image%@*}: $t"
		docker run --rm --network "$NET" --hostname host1.example.com \
			-v "$W/install.sh:/t/install.sh:ro" \
			-v "$ROOT/test/install/$t.sh:/t/$t.sh:ro" \
			-v "$ROOT/test/install/packages.sh:/t/packages.sh:ro" \
			-v "$W/release-signers:/t/release-signers:ro" \
			-v "$W/other-signers:/t/other-signers:ro" \
			-e URL="http://$NET-web:8000" -e RELEASE="$version" -e NEXT_RELEASE="$next" \
			"$image" sh "/t/$t.sh"
	done
done

log "PASS"
