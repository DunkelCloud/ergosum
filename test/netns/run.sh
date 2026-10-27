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
#
# Needs root, iproute2, curl, jq and ssh-keygen. Usage: sudo test/netns/run.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
W=$(mktemp -d /tmp/ergosum-netns.XXXXXX)
PIDS=()

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
	set +e
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
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
cat > "$W/serve.yaml" <<EOF
instance: authority-a
trust_domain: example.com
issuer: https://ergosum.example.com
signing_key: $W/signing.key
journal: $W/authority/journal.db
unseal_socket: $W/authority/unseal.sock
listen: ":7431"
ops_listen: "127.0.0.1:7433"
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

ops() { in_ns authority curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:7433$1" || true; }
for _ in $(seq 50); do [ "$(ops /healthz)" = 503 ] && break; sleep 0.2; done
[ "$(ops /healthz)" = 503 ] || fail "authority not up and sealed"
in_ns authority curl -s http://127.0.0.1:7433/metrics | grep -q '^machine_identity_authority_sealed 1' || fail "sealed metric"
if in_ns host1 curl -sk --max-time 2 https://198.51.100.2:7431/v1/keys >/dev/null; then fail "API reachable while sealed"; fi

log "unseal"
echo "wrong" | in_ns authority "$BIN/ergosum" unseal -socket "$W/authority/unseal.sock" && fail "wrong passphrase accepted"
echo "$PASS" | in_ns authority "$BIN/ergosum" unseal -socket "$W/authority/unseal.sock"
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
daemon_config host1 https://198.51.100.2:7431 '[]'
HOST1_FP=$(in_ns host1 "$BIN/ergosumd" fingerprint --config "$W/host1/ergosumd.yaml")
printf 'ergosum binding v1\nkind binding.set\ntrust-domain example.com\nidentity host1.example.com\nepoch 1\nkey %s\ncheck net 198.51.100.0/24\n' "$HOST1_FP" > "$W/event.txt"
ssh-keygen -q -Y sign -f "$W/alice" -n ergosum-binding "$W/event.txt"
jq -n --arg key "$HOST1_FP" --rawfile sig "$W/event.txt.sig" '{
	v: 1, kind: "binding.set", trust_domain: "example.com", identity: "host1.example.com",
	epoch: 1, key: $key, checks: [{type: "net", target: "198.51.100.0/24"}], signatures: [$sig]
}' > "$W/event.json"
code=$(in_ns host1 curl -sk -o "$W/bind.out" -w '%{http_code}' -H 'Content-Type: application/json' \
	--data @"$W/event.json" https://198.51.100.2:7431/v1/bindings)
[ "$code" = 201 ] || { cat "$W/bind.out"; fail "binding write returned $code"; }

log "host1 obtains a token"
in_ns host1 "$BIN/ergosumd" run --config "$W/host1/ergosumd.yaml" --log-format text > "$W/host1.log" 2>&1 &
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

log "clone of host1 in the other segment"
cp -a "$W/host1/state" "$W/clone-state"
for variant in auto lying; do
	addrs='[]'
	[ "$variant" = lying ] && addrs='["198.51.100.20"]'
	daemon_config "clone-$variant" https://203.0.113.2:7431 "$addrs"
	cp "$W/clone-state/identity.key" "$W/clone-$variant/state/"
	in_ns clone timeout 8 "$BIN/ergosumd" run --config "$W/clone-$variant/ergosumd.yaml" --log-format text > "$W/clone-$variant.log" 2>&1 || true
	[ -e "$W/clone-$variant/run/token" ] && fail "clone ($variant) received a token"
	grep -q 'denied' "$W/clone-$variant.log" || { cat "$W/clone-$variant.log"; fail "clone ($variant) not denied"; }
done

log "metrics"
metrics=$(in_ns authority curl -s http://127.0.0.1:7433/metrics)
echo "$metrics" | grep '^machine_identity_requests_total'
echo "$metrics" | grep -q 'result="issued"} [1-9]' || fail "no issuance counted"
echo "$metrics" | grep -q 'result="wrong_location"} [2-9]' || fail "clone attempts not counted as wrong_location"
echo "$metrics" | grep -q 'result="key_duplicate"} 0' || fail "unexpected key_duplicate"
grep -q '"log_type":"audit"\|log_type=audit' "$W/authority.log" || fail "no audit entries"

log "OK"
