#!/usr/bin/env bash
# Integration test with the real binaries in Linux network namespaces.
#
#   host1 198.51.100.20 --veth-- 198.51.100.2 authority 203.0.113.2 --veth-- 203.0.113.40 clone
#        (segment 198.51.100.0/24)                         (outside 203.0.113.0/24)
#
# The authority starts sealed (encrypted signing key), is unsealed through
# its local socket, accepts an SSH-signed binding for host1 with a net
# check, and issues host1 a token. A copy of host1's state in the other
# segment is refused, also when it reports host1's address as its own.
# deploy/install.sh then updates host1 from a signed release to the
# ergosumd in NEXT, refuses a bad signature, a changed file and an older
# version, and goes back when the new binary gets no token.
#
# Needs root, iproute2, curl, jq and ssh-keygen. BIN and NEXT are builds
# with release versions, NEXT the newer (see .github/workflows/ci.yml).
# Usage: sudo BIN=dist NEXT=dist-next test/netns/run.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
NEXT=${NEXT:?set NEXT to a build of ergosumd newer than BIN}
INSTALL=$(cd "$(dirname "$0")/../.." && pwd)/deploy/install.sh
W=$(mktemp -d /tmp/ergosum-netns.XXXXXX)
PIDS=()

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
	set +e
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	[ -f "$W/host1.pid" ] && kill "$(cat "$W/host1.pid")" 2>/dev/null
	wait 2>/dev/null
	for ns in authority host1 clone; do ip netns del "$ns" 2>/dev/null; done
	if [ "${KEEP:-}" = "" ]; then rm -rf "$W"; fi
}
trap cleanup EXIT

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

log "network"
for ns in authority host1 clone; do
	ip netns add "$ns"
	in_ns "$ns" ip link set lo up
done
# Direct veth pairs; no bridge, so the host's firewall is not involved.
ip link add seg netns authority type veth peer name eth0 netns host1
ip link add out netns authority type veth peer name eth0 netns clone
addr() { in_ns "$1" ip addr add "$3" dev "$2"; in_ns "$1" ip link set "$2" up; }
addr authority seg 198.51.100.2/24
addr authority out 203.0.113.2/24
addr host1 eth0 198.51.100.20/24
addr clone eth0 203.0.113.40/24

log "authority key (encrypted) and admin key"
PASS="netns test passphrase"
echo "$PASS" | "$BIN/ergosum" keygen -out "$W/signing.key" -encrypt > "$W/keygen.txt"
AUTH_FP=$(awk '/^fingerprint:/ {print $2}' "$W/keygen.txt")
[ -n "$AUTH_FP" ] || fail "no fingerprint from keygen"
ssh-keygen -q -t ed25519 -N "" -C alice@example.com -f "$W/alice"

mkdir -p "$W/authority"
# The authority list: an overlay and an IPv6 address that host1 cannot
# reach from its addresses, then the one it can.
cat > "$W/authorities.yaml" <<EOF
serial: 1
authorities:
  - key: $AUTH_FP
    urls: [https://100.64.0.2:7432, "https://[2001:db8::2]:7432", https://198.51.100.2:7432]
EOF
cat > "$W/serve.yaml" <<EOF
instance: authority-a
trust_domain: example.com
issuer: https://ergosum.example.com
signing_key: $W/signing.key
journal: $W/authority/journal.db
control_socket: $W/authority/control.sock
listen: ":7432"
listen_all_interfaces: true  # reached on both test networks
ops_listen: "127.0.0.1:7434"
authorities_file: $W/authorities.yaml
callbacks:
  networks:
    - cidr: 198.51.100.0/24
      source: 198.51.100.2
registry:
  admins:
    alice: "$(cat "$W/alice.pub")"
  approvals:
    binding.set: {threshold: 1, keys: [alice]}
    binding.revoked: {threshold: 1, keys: [alice]}
EOF
in_ns authority "$BIN/ergosum" serve --config "$W/serve.yaml" --log-format text > "$W/authority.log" 2>&1 &
PIDS+=($!)

ops() { in_ns authority curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:7434$1" || true; }
for _ in $(seq 50); do [ "$(ops /healthz)" = 503 ] && break; sleep 0.2; done
[ "$(ops /healthz)" = 503 ] || fail "authority not up and sealed"
in_ns authority curl -s http://127.0.0.1:7434/metrics | grep -q '^machine_identity_authority_sealed 1' || fail "sealed metric"
if in_ns host1 curl -sk --max-time 2 https://198.51.100.2:7432/v1/keys >/dev/null; then fail "API reachable while sealed"; fi

log "unseal"
echo "wrong" | in_ns authority "$BIN/ergosum" unseal -socket "$W/authority/control.sock" && fail "wrong passphrase accepted"
echo "$PASS" | in_ns authority "$BIN/ergosum" unseal -socket "$W/authority/control.sock"
for _ in $(seq 50); do [ "$(ops /healthz)" = 200 ] && break; sleep 0.2; done
[ "$(ops /healthz)" = 200 ] || fail "not unsealed"

daemon_config() { # name url addresses
	mkdir -p "$W/$1/state" "$W/$1/run"
	cat > "$W/$1/ergosumd.yaml" <<EOF
identity: host1.example.com
state_dir: $W/$1/state
token_file: $W/$1/run/token
token_group: "-"
metrics_file: $W/$1/run/ergosum.prom
addresses: $3
authorities:
  - url: $2
    key: "$AUTH_FP"
EOF
}

log "enroll host1"
daemon_config host1 https://198.51.100.2:7432 '[]'
HOST1_FP=$(in_ns host1 "$BIN/ergosumd" fingerprint --config "$W/host1/ergosumd.yaml")
printf 'ergosum binding v1\nkind binding.set\ntrust-domain example.com\nidentity host1.example.com\nepoch 1\nkey %s\ncheck net 198.51.100.0/24\n' "$HOST1_FP" > "$W/event.txt"
ssh-keygen -q -Y sign -f "$W/alice" -n ergosum-binding "$W/event.txt"
jq -n --arg key "$HOST1_FP" --rawfile sig "$W/event.txt.sig" '{
	v: 1, kind: "binding.set", trust_domain: "example.com", identity: "host1.example.com",
	epoch: 1, key: $key, checks: [{type: "net", target: "198.51.100.0/24"}], signatures: [$sig]
}' > "$W/event.json"
code=$(in_ns host1 curl -sk -o "$W/bind.out" -w '%{http_code}' -H 'Content-Type: application/json' \
	--data @"$W/event.json" https://198.51.100.2:7432/v1/bindings)
[ "$code" = 201 ] || { cat "$W/bind.out"; fail "binding write returned $code"; }

log "host1 obtains a token"
in_ns host1 "$BIN/ergosumd" run --config "$W/host1/ergosumd.yaml" --log-format text > "$W/host1.log" 2>&1 &
HOST1_PID=$!
PIDS+=($!)
for _ in $(seq 50); do [ -s "$W/host1/run/token" ] && break; sleep 0.2; done
[ -s "$W/host1/run/token" ] || { cat "$W/host1.log" "$W/authority.log"; fail "no token for host1"; }
b64url_decode() {
	local s; s=$(tr '_-' '/+')
	case $(( ${#s} % 4 )) in 2) s="$s==" ;; 3) s="$s=" ;; esac
	printf '%s' "$s" | base64 -d
}
claims=$(cut -d. -f2 "$W/host1/run/token" | b64url_decode)
echo "$claims" | jq -e '.sub == "spiffe://example.com/host/host1.example.com" and .aud == ["vault"] and .checks == ["key","net"]' >/dev/null \
	|| fail "unexpected claims: $claims"
perm=$(stat -c %a "$W/host1/run/token")
[ "$perm" = 640 ] || fail "token mode $perm"
jq -e '.serial == 1 and (.authorities[0].urls | length) == 3' "$W/host1/state/authorities.json" >/dev/null ||
	fail "authority list not stored"
grep -q '^machine_identity_authorities_serial 1$' "$W/host1/run/ergosum.prom" || fail "list serial not reported"

log "clone of host1 in the other segment"
# Every request with host1's key counts against host1 at the authority: ten
# at once, then one a minute. The update below still needs its share, so
# each clone stops at its first denial.
cp -a "$W/host1/state" "$W/clone-state"
for variant in auto lying; do
	addrs='[]'
	[ "$variant" = lying ] && addrs='["198.51.100.20"]'
	daemon_config "clone-$variant" https://203.0.113.2:7432 "$addrs"
	cp "$W/clone-state/identity.key" "$W/clone-$variant/state/"
	ip netns exec clone "$BIN/ergosumd" run --config "$W/clone-$variant/ergosumd.yaml" --log-format text > "$W/clone-$variant.log" 2>&1 &
	clone_pid=$!
	for _ in $(seq 80); do grep -q 'denied' "$W/clone-$variant.log" && break; sleep 0.1; done
	kill "$clone_pid" 2>/dev/null || true
	wait "$clone_pid" 2>/dev/null || true
	[ -e "$W/clone-$variant/run/token" ] && fail "clone ($variant) received a token"
	grep -q 'denied' "$W/clone-$variant.log" || { cat "$W/clone-$variant.log"; fail "clone ($variant) not denied"; }
done

log "metrics"
metrics=$(in_ns authority curl -s http://127.0.0.1:7434/metrics)
echo "$metrics" | grep '^machine_identity_requests_total'
echo "$metrics" | grep -q 'result="issued"} [1-9]' || fail "no issuance counted"
echo "$metrics" | grep -q 'result="wrong_location"} [2-9]' || fail "clone attempts not counted as wrong_location"
echo "$metrics" | grep -q 'result="key_duplicate"} 0' || fail "unexpected key_duplicate"
version=$("$BIN/ergosum" version | cut -d' ' -f2)
echo "$metrics" | grep "^machine_identity_build_info{version=\"$version\"," || fail "authority reports no build_info for $version"
grep -q "^machine_identity_build_info{version=\"$version\"," "$W/host1/run/ergosum.prom" || fail "daemon reports no build_info for $version"
grep -q '"log_type":"audit"\|log_type=audit' "$W/authority.log" || fail "no audit entries"

log "update host1 with deploy/install.sh"
# host1's daemon now runs from a directory the script installs into and is
# restarted the way a service manager would do it.
kill "$HOST1_PID"
wait "$HOST1_PID" 2>/dev/null || true
mkdir -p "$W/bin"
cp "$BIN/ergosumd" "$W/bin/ergosumd"
cat > "$W/restart-host1" <<EOF
if [ -f "$W/host1.pid" ]; then
	pid=\$(cat "$W/host1.pid")
	kill "\$pid" 2>/dev/null
	while kill -0 "\$pid" 2>/dev/null; do sleep 0.1; done
fi
ip netns exec host1 "$W/bin/ergosumd" run --config "$W/host1/ergosumd.yaml" --log-format text >> "$W/host1.log" 2>&1 &
echo \$! > "$W/host1.pid"
EOF
sh "$W/restart-host1"

arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
ssh-keygen -q -t ed25519 -N "" -C release -f "$W/release-key"
echo "release namespaces=\"ergosum-release\" $(cat "$W/release-key.pub")" > "$W/release-signers"
ssh-keygen -q -t ed25519 -N "" -C other -f "$W/other-key"
echo "release namespaces=\"ergosum-release\" $(cat "$W/other-key.pub")" > "$W/other-signers"
release() { # name ergosumd-binary
	mkdir -p "$W/$1"
	cp "$2" "$W/$1/ergosumd-linux-$arch"
	(cd "$W/$1" && sha256sum "ergosumd-linux-$arch" > SHA256SUMS)
	ssh-keygen -q -Y sign -f "$W/release-key" -n ergosum-release "$W/$1/SHA256SUMS"
}
install_release() { # [signers] options... dir
	local signers=$W/release-signers
	[ "$1" = --other ] && { signers=$W/other-signers; shift; }
	BINDIR="$W/bin" RESTART_CMD="sh $W/restart-host1" sh "$INSTALL" \
		--signers "$signers" --config "$W/host1/ergosumd.yaml" --wait 20 "$@"
}
installed() { "$W/bin/ergosumd" version | awk '{print $2}'; }
old=$("$BIN/ergosumd" version | awk '{print $2}')
new=$("$NEXT/ergosumd" version | awk '{print $2}')

release next "$NEXT/ergosumd"
if out=$(install_release --other "$W/next" 2>&1); then fail "installed with a foreign signature: $out"; fi
echo "$out" | grep -q 'does not verify' || fail "foreign signature: $out"
cp -r "$W/next" "$W/changed"
printf x >> "$W/changed/ergosumd-linux-$arch"
if out=$(install_release "$W/changed" 2>&1); then fail "installed a changed file: $out"; fi
echo "$out" | grep -q 'does not match SHA256SUMS' || fail "changed file: $out"
[ "$(installed)" = "$old" ] || fail "binary replaced by a refused release"

install_release "$W/next" || fail "update to $new failed"
[ "$(installed)" = "$new" ] || fail "installed $(installed), not $new"
[ "$("$W/bin/ergosumd.old" version | awk '{print $2}')" = "$old" ] || fail "previous binary not kept"
grep -q "^machine_identity_build_info{version=\"$new\"," "$W/host1/run/ergosum.prom" || fail "daemon does not report $new"
install_release "$W/next" | grep -q 'already installed' || fail "same version installed again"

release older "$BIN/ergosumd"
if out=$(install_release "$W/older" 2>&1); then fail "installed an older version: $out"; fi
echo "$out" | grep -q 'is older than' || fail "older version: $out"

cat > "$W/broken-ergosumd" <<'EOF'
#!/bin/sh
# Claims a newer version, but does not run.
[ "$1" = version ] && { echo "ergosumd v99.0.0 (broken)"; exit 0; }
exit 1
EOF
release broken "$W/broken-ergosumd"
if out=$(install_release "$W/broken" 2>&1); then fail "broken binary kept: $out"; fi
echo "$out" | grep -q "$new is back and has a new token" || { tail -n 20 "$W/host1.log"; fail "no way back: $out"; }
[ "$(installed)" = "$new" ] || fail "after the way back $(installed) runs, not $new"

log "OK"
