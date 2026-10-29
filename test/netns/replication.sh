#!/usr/bin/env bash
# Journal replication with the real binaries in Linux network namespaces.
#
#            authority-a
#   192.0.2.1 /       \ 192.0.2.5
#            /         \
#   192.0.2.2           192.0.2.6
#  authority-b --------- authority-c
#            192.0.2.9   192.0.2.10
#            |
#   198.51.100.2 --- 198.51.100.20 host1 (segment 198.51.100.0/24)
#
# Two administrators approve a binding at a, each with "ergosum bind" on
# the same file (ssh-keygen signatures, approvals 2); it replicates to b,
# where host1 obtains its token. b misses events while it is down and
# catches up; a partition between a and b with one event on each side
# converges. a writes a checkpoint and compacts, and c, a new instance,
# builds its journal with "ergosum journal sync".
#
# Needs root, iproute2, curl, jq and ssh-keygen. Usage:
#   sudo BIN=dist test/netns/replication.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
W=$(mktemp -d /tmp/ergosum-repl.XXXXXX)
declare -A PID
NS=(a b c host1)

log() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	for n in a b c; do [ -f "$W/$n.log" ] && { echo "--- $n.log"; tail -n 30 "$W/$n.log"; }; done >&2
	exit 1
}

cleanup() {
	set +e
	for p in "${PID[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	for ns in "${NS[@]}"; do ip netns del "$ns" 2>/dev/null; done
	if [ "${KEEP:-}" = "" ]; then rm -rf "$W"; fi
}
trap cleanup EXIT

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

log "network"
for ns in "${NS[@]}"; do
	ip netns add "$ns"
	in_ns "$ns" ip link set lo up
done
link() { # ns1 if1 addr1 ns2 if2 addr2
	ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
	in_ns "$1" ip addr add "$3" dev "$2"; in_ns "$1" ip link set "$2" up
	in_ns "$4" ip addr add "$6" dev "$5"; in_ns "$4" ip link set "$5" up
}
link a ab 192.0.2.1/30 b ba 192.0.2.2/30
link a ac 192.0.2.5/30 c ca 192.0.2.6/30
link b bc 192.0.2.9/30 c cb 192.0.2.10/30
link b seg 198.51.100.2/24 host1 eth0 198.51.100.20/24

log "keys"
declare -A FP PUB
for n in a b c; do
	mkdir -p "$W/$n"
	"$BIN/ergosum" keygen -out "$W/$n/signing.key" > "$W/$n/keygen.txt"
	FP[$n]=$(awk '/^fingerprint:/ {print $2}' "$W/$n/keygen.txt")
	PUB[$n]=$(sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' "$W/$n/keygen.txt" | sed 's/^/        /')
done
for adm in alice bob; do ssh-keygen -q -t ed25519 -N "" -C "$adm@example.com" -f "$W/$adm"; done

peer() { # name url
	printf '    - name: authority-%s\n' "$1"
	[ -n "$2" ] && printf '      url: %s\n' "$2"
	printf '      fingerprint: "%s"\n      key: |\n%s\n' "${FP[$1]}" "${PUB[$1]}"
}
config() { # name peers...
	local n=$1; shift
	cat > "$W/$n/serve.yaml" <<EOF
instance: authority-$n
trust_domain: example.com
issuer: https://ergosum.example.com
signing_key: $W/$n/signing.key
journal: $W/$n/journal.db
control_socket: $W/$n/control.sock
listen: ":7432"
listen_all_interfaces: true  # reached on several test links
ops_listen: "127.0.0.1:7434"
callbacks:
  networks:
    - cidr: 198.51.100.0/24
registry:
  admins:
    alice: "$(cat "$W/alice.pub")"
    bob: "$(cat "$W/bob.pub")"
  approvals:
    binding.set: {threshold: 2, keys: [alice, bob]}
    binding.revoked: {threshold: 2, keys: [alice, bob]}
compaction:
  retention:
    observations: 1s
    bindings: 1s
replication:
  listen: ":7435"
  peers:
EOF
	for p in "$@"; do peer ${p%%=*} "${p#*=}" >> "$W/$n/serve.yaml"; done
}
# c is new: a and b know its key but do not push to it.
config a "b=https://192.0.2.2:7435" "c="
config b "a=https://192.0.2.1:7435" "c="
config c "a=https://192.0.2.5:7435" "b=https://192.0.2.9:7435"

ops() { in_ns "$1" curl -s --max-time 2 "http://127.0.0.1:7434$2" || true; }
state() { ops "$1" /v1/journal/state; }
hash_of() { state "$1" | jq -r '.state_hash // empty'; }
same_state() { local h; h=$(hash_of "$1"); [ -n "$h" ] && [ "$h" = "$(hash_of "$2")" ]; }
wait_for() { # what command...
	local what=$1; shift
	for _ in $(seq 150); do "$@" && return 0; sleep 0.2; done
	fail "$what"
}
healthy() { [ "$(in_ns "$1" curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7434/healthz)" = 200 ]; }
start() {
	# Directly, not through in_ns: $! must be the instance, so that stop ends it.
	ip netns exec "$1" "$BIN/ergosum" serve --config "$W/$1/serve.yaml" --log-format text >> "$W/$1.log" 2>&1 &
	PID[$1]=$!
	wait_for "authority-$1 up" healthy "$1"
	kill -0 "${PID[$1]}" 2>/dev/null || fail "authority-$1 exited"
}
stop() {
	kill "${PID[$1]}"
	wait "${PID[$1]}" 2>/dev/null || true
	unset "PID[$1]"
	if [ "$1" != host1 ] && healthy "$1"; then fail "authority-$1 still answers after stop"; fi
}
start a
start b

# The administrators' tool, run in a's namespace against a's API.
cat > "$W/admin.yaml" <<EOF
trust_domain: example.com
authorities:
  - url: https://127.0.0.1:7432
    key: "${FP[a]}"
EOF
export ERGOSUM_ADMIN_CONFIG=$W/admin.yaml
ergosum_at() { local ns=$1; shift; in_ns "$ns" "$BIN/ergosum" "$@"; }
# approve NS AUTHORITY_FP IDENTITY KEY TYPE:TARGET: alice and bob sign the
# same binding file one after the other; the second signature records it.
approve() {
	local ns=$1 fp=$2 id=$3 key=$4 check=$5 f="$W/binding-$RANDOM.txt"
	local at=(-authority https://127.0.0.1:7432 -authority-key "$fp")
	printf 'identity %s\nkey %s\ncheck %s\n' "$id" "$key" "${check/:/ }" > "$f"
	ergosum_at "$ns" bind "${at[@]}" -sign-key "$W/alice" -yes "$f" 2>> "$W/admin.log" \
		|| { cat "$W/admin.log"; fail "alice could not sign the binding for $id"; }
	grep -q '^# recorded' "$f" && fail "one approval of two was accepted"
	ergosum_at "$ns" bind "${at[@]}" -sign-key "$W/bob" -yes "$f" 2>> "$W/admin.log" \
		|| { cat "$W/admin.log"; fail "binding for $id not recorded"; }
	grep -q '^# recorded' "$f" || { cat "$W/admin.log"; fail "binding for $id not recorded"; }
}

log "four-eyes binding at a, token from b"
mkdir -p "$W/host1/state" "$W/host1/run"
cat > "$W/host1/ergosumd.yaml" <<EOF
identity: host1.example.com
state_dir: $W/host1/state
token_file: $W/host1/run/token
token_group: "-"
metrics_file: $W/host1/run/ergosum.prom
authorities:
  - url: https://198.51.100.2:7432
    key: "${FP[b]}"
EOF
HOST1_FP=$(in_ns host1 "$BIN/ergosumd" fingerprint --config "$W/host1/ergosumd.yaml")
approve a "${FP[a]}" host1.example.com "$HOST1_FP" net:198.51.100.0/24
wait_for "binding replicated to b" same_state a b
ip netns exec host1 "$BIN/ergosumd" run --config "$W/host1/ergosumd.yaml" --log-format text > "$W/host1.log" 2>&1 &
PID[host1]=$!
wait_for "host1 token from b" test -s "$W/host1/run/token"
stop host1
issued_at_a() { state a | jq -e '.events >= 2' > /dev/null; }
wait_for "b's observation replicated to a" issued_at_a

log "b catches up after an outage"
stop b
OTHER_FP=$("$BIN/ergosum" keygen -out "$W/other.key" | awk '/^fingerprint:/ {print $2}')
approve a "${FP[a]}" host2.example.com "$OTHER_FP" tailnet:host2.tailnet.example.com
pending_at_a() { [ "$(state a | jq '.peers[0].pending')" -gt 0 ]; }
pending_at_a || fail "no outbox while b is down: $(state a)"
start b
wait_for "b caught up" same_state a b

log "partition between a and b"
in_ns a ip link set ab down
approve a "${FP[a]}" host3.example.com "$OTHER_FP" tailnet:host3.tailnet.example.com
approve b "${FP[b]}" host3.example.com "$HOST1_FP" tailnet:host3.tailnet.example.com
same_state a b && fail "partitioned instances already agree"
in_ns a ip link set ab up
wait_for "convergence after the partition" same_state a b

log "checkpoint and compaction at a"
ergosum_at a journal checkpoint -socket "$W/a/control.sock" > /dev/null
acked() { [ "$(state a | jq '.peers[0].pending')" = 0 ]; }
wait_for "b acknowledged the checkpoint" acked
sleep 1.1 # past the retention of one second
deleted=$(ergosum_at a journal compact -socket "$W/a/control.sock" | jq .deleted)
[ "$deleted" -gt 0 ] || fail "compaction deleted nothing"
same_state a b || fail "compaction changed the projection"

log "c is built from a sync"
start c
ergosum_at c journal sync -from authority-a -from authority-b -socket "$W/c/control.sock" > "$W/sync.json"
jq -e '.[0].checkpoint == true' "$W/sync.json" > /dev/null || fail "sync did not start with a's checkpoint: $(cat "$W/sync.json")"
same_state a c || fail "c differs from a after the sync"

log "export and metrics"
ergosum_at a journal export -out "$W/a.jsonl" -socket "$W/a/control.sock" 2> /dev/null
[ "$(wc -l < "$W/a.jsonl")" -gt 0 ] || fail "empty export"
metrics=$(ops a /metrics)
echo "$metrics" | grep '^machine_identity_journal_' | grep -v '^#'
echo "$metrics" | grep -q 'machine_identity_journal_outbox_events{peer="authority-b"} 0' || fail "outbox metric"
echo "$metrics" | grep -q 'machine_identity_journal_rejected_total{peer="authority-b"} 0' || fail "rejections"

log "OK"
