#!/usr/bin/env bash
# Secrets without Vault (ADR 0004) with the real binaries in Linux network
# namespaces.
#
#   authority-a 10.0.1.1 --- 10.0.1.2 \
#   authority-b 10.0.2.1 --- 10.0.2.2  host1 (192.0.2.10, bound with "ip")
#   authority-c 10.0.3.1 --- 10.0.3.2 /
#   authority-a 10.0.4.1 --- 10.0.4.2   clone (a copy of host1's disk)
#
# host1 seals a secret with a threshold of 2 at a and b, the instances of
# list 1, and reads it back with "ergosumd secret get", byte for byte, also
# after a restart of its daemon; with a down it does not open. A user who
# cannot read part A gets nothing. List 2 adds c: the daemon re-splits the
# held secret, the next get replaces part A, and the new part A opens with
# b and c while a is down. A copy of host1's disk elsewhere opens nothing.
# Part A created with a relative -file lies in the working directory:
# create names the absolute -file that get needs, get NAME alone says that
# it looked only in the secrets directory, and get with that -file opens it
# from elsewhere.
#
# Needs root, iproute2, curl, jq, ssh-keygen and setpriv. Usage:
#   sudo BIN=dist test/netns/secrets.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
W=$(mktemp -d /tmp/ergosum-secrets.XXXXXX)
chmod 0755 "$W"
declare -A PID
NS=(a b c host1 clone)

log() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	for f in "$W"/*.log; do [ -f "$f" ] && { echo "--- $f"; tail -n 25 "$f"; }; done >&2
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
wait_for() { # seconds what command...
	local t=$1 what=$2
	shift 2
	for _ in $(seq $((t * 5))); do "$@" && return 0; sleep 0.2; done
	fail "timed out: $what"
}

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
link a ah 10.0.1.1/30 host1 ha 10.0.1.2/30
link b bh 10.0.2.1/30 host1 hb 10.0.2.2/30
link c ch 10.0.3.1/30 host1 hc 10.0.3.2/30
link a ak 10.0.4.1/30 clone ka 10.0.4.2/30
# The copied list names a at 10.0.1.1; the clone reaches it over its link.
in_ns clone ip route add 10.0.1.0/30 via 10.0.4.1
# host1's bound address; each instance reaches it over its own link.
in_ns host1 ip link add pub type dummy
in_ns host1 ip addr add 192.0.2.10/32 dev pub
in_ns host1 ip link set pub up
for n in a b c; do
	i=$(( $(printf '%d' "'$n") - 96 ))
	in_ns "$n" ip route add 192.0.2.10/32 via "10.0.$i.2"
done

log "keys"
declare -A FP
for n in a b c; do
	mkdir -p "$W/$n"
	"$BIN/ergosum" keygen -out "$W/$n/signing.key" > "$W/$n/keygen.txt"
	"$BIN/ergosum" keygen -exchange -out "$W/$n/exchange.key" > /dev/null
	FP[$n]=$(awk '/^fingerprint:/ {print $2}' "$W/$n/keygen.txt")
done
ssh-keygen -q -t ed25519 -N "" -C alice@example.com -f "$W/alice"
url() { local i=$(( $(printf '%d' "'$1") - 96 )); echo "https://10.0.$i.1:7432"; }

list() { # file serial instances...
	local f=$1 serial=$2
	shift 2
	{
		echo "serial: $serial"
		echo "authorities:"
		for n in "$@"; do printf '  - key: "%s"\n    urls: [%s]\n' "${FP[$n]}" "$(url "$n")"; done
	} > "$f.tmp"
	mv "$f.tmp" "$f"
}
for n in a b c; do
	cat > "$W/$n/serve.yaml" <<EOF
instance: authority-$n
trust_domain: example.com
issuer: https://ergosum.example.com
token_ttl: 20s
signing_key: $W/$n/signing.key
exchange_key_file: $W/$n/exchange.key
journal: $W/$n/journal.db
control_socket: $W/$n/control.sock
listen: ":7432"
listen_all_interfaces: true  # reached on several test links
ops_listen: "127.0.0.1:7434"
authorities_file: $W/$n/authorities.yaml
registry:
  admins:
    alice: "$(cat "$W/alice.pub")"
  approvals:
    binding.set: {threshold: 1, keys: [alice]}
    binding.revoked: {threshold: 1, keys: [alice]}
EOF
done
# c is not in list 1, and an instance starts only with a list naming it.
list "$W/a/authorities.yaml" 1 a b
list "$W/b/authorities.yaml" 1 a b
list "$W/c/authorities.yaml" 1 c

healthy() { [ "$(in_ns "$1" curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7434/healthz)" = 200 ]; }
start() {
	ip netns exec "$1" "$BIN/ergosum" serve --config "$W/$1/serve.yaml" --log-format text >> "$W/$1.log" 2>&1 &
	PID[$1]=$!
	wait_for 10 "authority-$1 up" healthy "$1"
}
stop() {
	kill "${PID[$1]}"
	wait "${PID[$1]}" 2>/dev/null || true
	unset "PID[$1]"
}
metric() { # ns name labels
	in_ns "$1" curl -s http://127.0.0.1:7434/metrics | awk -v m="$2$3" '$1 == m {print $2}'
}
for n in a b c; do start "$n"; done

log "host1 and its binding at every instance"
mkdir -p "$W/host1/state" "$W/host1/run" "$W/host1/secrets"
cat > "$W/host1/ergosumd.yaml" <<EOF
identity: host1.example.com
state_dir: $W/host1/state
token_file: $W/host1/run/token
token_group: "-"
metrics_file: $W/host1/run/ergosum.prom
callback_listen: ":7433"
authorities:
  - key: "${FP[a]}"
    url: $(url a)
EOF
FPH=$(in_ns host1 "$BIN/ergosumd" fingerprint --config "$W/host1/ergosumd.yaml")
printf 'ergosum binding v1\nkind binding.set\ntrust-domain example.com\nidentity host1.example.com\nepoch 1\nkey %s\ncheck ip 192.0.2.10\n' "$FPH" > "$W/binding.txt"
ssh-keygen -q -Y sign -f "$W/alice" -n ergosum-binding "$W/binding.txt"
jq -n --arg key "$FPH" --rawfile sig "$W/binding.txt.sig" '{
	v: 1, kind: "binding.set", trust_domain: "example.com", identity: "host1.example.com",
	epoch: 1, key: $key, checks: [{type: "ip", target: "192.0.2.10"}], signatures: [$sig]
}' > "$W/binding.json"
for n in a b c; do
	code=$(in_ns "$n" curl -sk -o "$W/bind.out" -w '%{http_code}' -H 'Content-Type: application/json' \
		--data @"$W/binding.json" "https://127.0.0.1:7432/v1/bindings")
	[ "$code" = 201 ] || { cat "$W/bind.out"; fail "binding at $n returned $code"; }
done

SOCK=$W/host1/run/secret.sock
daemon() { # ns
	ip netns exec "$1" "$BIN/ergosumd" run --config "$W/$1/ergosumd.yaml" --log-format text >> "$W/$1-daemon.log" 2>&1 &
	PID[$1]=$!
}
serial() { awk '$1 == "machine_identity_authorities_serial" {print $2}' "$W/host1/run/ergosum.prom" 2>/dev/null; }
has_serial() { [ "$(serial)" = "$1" ]; }
daemon host1
wait_for 20 "first token of host1" test -S "$SOCK"
wait_for 20 "list 1 at host1" has_serial 1
[ "$(stat -c %a "$SOCK")" = 600 ] || fail "secret socket is not 0600"

secret() { in_ns host1 "$BIN/ergosumd" secret "$@" -config "$W/host1/ergosumd.yaml" -socket "$SOCK"; }
PA=$W/host1/secrets/restic

log "create, threshold 2 of a and b"
printf 'it'"'"'s a secret\n' | secret create restic -threshold 2 -file "$PA" \
	-recovery "$(cat "$W/alice.pub")" 2> "$W/create.err" || { cat "$W/create.err"; fail "create"; }
[ "$(stat -c %a "$PA")" = 600 ] || fail "part A is not 0600"
secret info restic -file "$PA" | tee "$W/info.out"
grep -q '^threshold:    2 of 2' "$W/info.out" || fail "info: threshold"
grep -q '^recovery:     age file' "$W/info.out" || fail "info: recovery"
grep -q "it's a secret" "$PA" && fail "part A contains the secret"
printf 'it'"'"'s a secret' > "$W/want"
printf 'x' | secret create restic -threshold 2 -file "$PA" 2> /dev/null && fail "create overwrote part A"

log "get, byte for byte, also after a restart of the daemon"
secret get -file "$PA" > "$W/got" || fail "get"
cmp "$W/want" "$W/got" || fail "get returned other bytes"
before=$(metric a machine_identity_exchanges_total '{result="issued"}')
stop host1
daemon host1
wait_for 20 "socket after restart" test -S "$SOCK"
secret get -file "$PA" > "$W/got" || fail "get after restart"
cmp "$W/want" "$W/got" || fail "get after restart returned other bytes"
after=$(metric a machine_identity_exchanges_total '{result="issued"}')
[ "$after" -gt "$before" ] || fail "the get after a restart did not ask a ($before -> $after)"

log "a user who cannot read part A gets nothing"
if in_ns host1 setpriv --reuid=65534 --regid=65534 --clear-groups "$BIN/ergosumd" secret get -file "$PA" -socket "$SOCK" > "$W/got" 2> /dev/null; then
	fail "nobody got the secret"
fi
[ ! -s "$W/got" ] || fail "stdout not empty on failure"

log "a down: 1 of 2 shares"
stop a
stop host1
daemon host1
wait_for 20 "socket with a down" test -S "$SOCK"
if secret get -file "$PA" > "$W/got" 2> "$W/get.err"; then fail "opened with a down"; fi
[ ! -s "$W/got" ] || fail "stdout not empty on failure"
grep -q '1 of the 2 shares' "$W/get.err" || { cat "$W/get.err"; fail "error does not name the shares"; }
start a

log "list 2 adds c; the held secret is re-split"
for n in a b c; do list "$W/$n/authorities.yaml" 2 a b c; done
stop host1
daemon host1
wait_for 30 "list 2 at host1" has_serial 2
secret get -file "$PA" > "$W/got" || fail "get under list 2"
resplit() { secret get -file "$PA" > "$W/got" 2> "$W/get.err" && grep -q 're-split' "$W/get.err"; }
wait_for 60 "re-split part A handed over" resplit
cmp "$W/want" "$W/got" || fail "the get that re-split returned other bytes"
[ "$(stat -c %a "$PA")" = 600 ] || fail "re-split part A lost its mode"
secret info restic -file "$PA" | tee "$W/info.out"
grep -q '^threshold:    2 of 3' "$W/info.out" || fail "re-split part A: pins"
grep -q "${FP[c]}" "$W/info.out" || fail "re-split part A does not pin c"

log "the new part A opens with b and c"
stop a
stop host1
daemon host1
wait_for 20 "socket" test -S "$SOCK"
secret get -file "$PA" > "$W/got" || { cat "$W/host1-daemon.log" | tail -5; fail "new part A without a"; }
cmp "$W/want" "$W/got" || fail "new part A returned other bytes"
start a

log "a copy of host1's disk elsewhere opens nothing"
stop host1
mkdir -p "$W/clone/run"
cp -a "$W/host1/state" "$W/clone/state"
cp "$PA" "$W/clone/restic"
sed -e "s#$W/host1#$W/clone#g" "$W/host1/ergosumd.yaml" > "$W/clone/ergosumd.yaml"
daemon clone
wait_for 20 "socket of the clone" test -S "$W/clone/run/secret.sock"
if in_ns clone "$BIN/ergosumd" secret get -file "$W/clone/restic" -config "$W/clone/ergosumd.yaml" -socket "$W/clone/run/secret.sock" > "$W/got" 2> "$W/clone.err"; then
	fail "the clone opened the secret"
fi
[ ! -s "$W/got" ] || fail "stdout not empty for the clone"
denied=$(metric a machine_identity_exchanges_total '{result="wrong_location"}')
[ "${denied:-0}" -ge 1 ] || fail "no wrong_location exchange at a"

log "a relative -file is from the working directory, and get needs it"
stop clone
daemon host1
wait_for 20 "socket" test -S "$SOCK"
mkdir -p "$W/cwd"
printf 'elsewhere\n' | (cd "$W/cwd" && secret create netns-elsewhere -threshold 2 -file elsewhere) 2> "$W/create.err" ||
	{ cat "$W/create.err"; fail "create with a relative -file"; }
[ -f "$W/cwd/elsewhere" ] || fail "part A is not in the working directory of create"
if secret get netns-elsewhere > "$W/got" 2> "$W/get.err"; then fail "get NAME opened part A outside the secrets directory"; fi
[ ! -s "$W/got" ] || fail "stdout not empty on failure"
grep -q -- '-file' "$W/get.err" || { cat "$W/get.err"; fail "get NAME does not point to -file"; }
grep -q -- "-file $W/cwd/elsewhere\$" "$W/create.err" || { cat "$W/create.err"; fail "create does not name the -file for get"; }
secret get -file "$W/cwd/elsewhere" > "$W/got" || fail "get with the absolute -file"
printf 'elsewhere' | cmp - "$W/got" || fail "get with the absolute -file returned other bytes"

log "OK"
