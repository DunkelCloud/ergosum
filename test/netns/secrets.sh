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
# after a restart of its daemon. "secret replace" seals a new secret in
# place of part A with its threshold, owner and mode, and only with
# -recovery, since part A has a recovery copy; the old part A still opens
# the old secret. "secret edit" hands the secret to an editor in a file
# with mode 0600 in a directory of its own with mode 0700 on tmpfs, leaves
# part A alone if the editor fails or changes nothing, leaves no file
# behind, also after SIGTERM and SIGHUP, and refuses to start where no
# directory is in memory. With a down the secret does not open. A user who
# cannot read part A gets nothing. List 2 adds c: the daemon re-splits the
# held secret, the next get replaces part A, and the new part A opens with
# b and c while a is down. A copy of host1's disk elsewhere opens nothing.
# Part A created with a relative -file lies in the working directory:
# create names the absolute -file that get needs, get NAME alone says that
# it looked only in the secrets directory, and get with that -file opens it
# from elsewhere.
#
# Needs root, iproute2, curl, jq, ssh-keygen, and setpriv and unshare of
# util-linux. Usage:
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

log "replace: a new secret with the threshold, owner and mode of part A"
cp "$PA" "$W/partA.old"
if printf 'never\n' | secret replace restic -file "$PA" 2> "$W/replace.err"; then
	fail "replace without -recovery replaced a part A with a recovery copy"
fi
grep -q -- '-recovery' "$W/replace.err" || { cat "$W/replace.err"; fail "replace does not ask for -recovery"; }
cmp "$PA" "$W/partA.old" || fail "a refused replace changed part A"
if : | secret replace restic -file "$PA" -recovery "$(cat "$W/alice.pub")" 2> /dev/null; then
	fail "replace took an empty secret"
fi
cmp "$PA" "$W/partA.old" || fail "a refused replace changed part A"
chown 0:12345 "$PA"
chmod 0640 "$PA"
printf 'replaced\n' | secret replace restic -file "$PA" -recovery "$(cat "$W/alice.pub")" 2> "$W/replace.err" ||
	{ cat "$W/replace.err"; fail "replace"; }
[ "$(stat -c '%u:%g %a' "$PA")" = "0:12345 640" ] || fail "replace changed owner or mode: $(stat -c '%u:%g %a' "$PA")"
chown 0:0 "$PA"
chmod 0600 "$PA"
cmp -s "$PA" "$W/partA.old" && fail "replace left part A as it was"
[ "$(ls -A "$W/host1/secrets")" = restic ] || fail "replace left a file next to part A"
secret info restic -file "$PA" > "$W/info.out"
grep -q '^threshold:    2 of 2' "$W/info.out" || { cat "$W/info.out"; fail "replace changed the threshold or the pins"; }
grep -q '^recovery:     age file' "$W/info.out" || fail "replace lost the recovery copy"
printf 'replaced' > "$W/want"
secret get -file "$PA" > "$W/got" || fail "get after replace"
cmp "$W/want" "$W/got" || fail "get after replace returned other bytes"
# No revocation: the old part A still opens the old secret.
secret get -file "$W/partA.old" > "$W/got" || fail "get of the old part A"
printf 'it'"'"'s a secret' | cmp - "$W/got" || fail "the old part A returned other bytes"

log "edit: the text on tmpfs in a directory of its own, and nothing left behind"
# The editor notes where its file lies, then runs $EDITOR_DOES on it.
cat > "$W/editor" <<'EOF'
#!/bin/sh
f=$1
d=$(dirname "$f")
printf '%s %s %s %s\n' "$(stat -f -c %T "$d")" "$(stat -c %a "$d")" "$(stat -c %a "$f")" "$d" > "$EDITOR_REPORT"
eval "$EDITOR_DOES"
EOF
chmod 0755 "$W/editor"
REPORT=$W/editor.report
edit() { # what the editor does, arguments of edit...
	local does=$1
	shift
	rm -f "$REPORT"
	VISUAL='' EDITOR="$W/editor" EDITOR_REPORT="$REPORT" EDITOR_DOES="$does" \
		secret edit restic -file "$PA" -recovery "$(cat "$W/alice.pub")" "$@"
}
edited_in_memory() { # the editor's file was on tmpfs or ramfs with mode 600 in a directory with 700, now gone
	local fs dmode fmode dir
	read -r fs dmode fmode dir < "$REPORT" || fail "the editor did not run"
	case $fs in tmpfs | ramfs) ;; *) fail "the editor's file was on $fs" ;; esac
	[ "$dmode" = 700 ] && [ "$fmode" = 600 ] || fail "the editor's file had mode $fmode in a directory with mode $dmode"
	[ ! -e "$dir" ] || fail "edit left $dir behind"
}
edit 'printf "edited\nsecond line\n" > "$f"' 2> "$W/edit.err" || { cat "$W/edit.err"; fail "edit"; }
edited_in_memory
printf 'edited\nsecond line' > "$W/want"
secret get -file "$PA" > "$W/got" || fail "get after edit"
cmp "$W/want" "$W/got" || fail "get after edit returned other bytes"
secret info restic -file "$PA" > "$W/info.out"
grep -q '^threshold:    2 of 2' "$W/info.out" || { cat "$W/info.out"; fail "edit changed the threshold or the pins"; }
grep -q '^recovery:     age file' "$W/info.out" || fail "edit lost the recovery copy"
[ "$(stat -c %a "$PA")" = 600 ] || fail "edit changed the mode of part A"

log "edit: no change, a failing editor, an empty file and a signal leave part A alone"
cp "$PA" "$W/partA.edited"
edit true 2> "$W/edit.err" || { cat "$W/edit.err"; fail "edit without a change did not end with 0"; }
grep -q 'not replaced' "$W/edit.err" || { cat "$W/edit.err"; fail "edit without a change does not say so"; }
edited_in_memory
cmp "$PA" "$W/partA.edited" || fail "edit without a change replaced part A"
if edit 'echo spoiled > "$f"; exit 3' 2> /dev/null; then fail "edit took what a failing editor left"; fi
edited_in_memory
cmp "$PA" "$W/partA.edited" || fail "a failing editor changed part A"
if edit ': > "$f"' 2> /dev/null; then fail "edit took an empty secret"; fi
edited_in_memory
cmp "$PA" "$W/partA.edited" || fail "an empty file changed part A"
for sig in TERM HUP; do
	rm -f "$REPORT"
	VISUAL='' EDITOR="$W/editor" EDITOR_REPORT="$REPORT" EDITOR_DOES='exec sleep 60' \
		ip netns exec host1 "$BIN/ergosumd" secret edit restic -file "$PA" -recovery "$(cat "$W/alice.pub")" \
		-config "$W/host1/ergosumd.yaml" -socket "$SOCK" 2> "$W/edit.err" &
	pid=$!
	wait_for 20 "the editor to open" test -s "$REPORT"
	kill -s "$sig" "$pid"
	if wait "$pid"; then fail "edit ended with 0 after SIG$sig"; fi
	grep -q 'ended by a signal' "$W/edit.err" || { cat "$W/edit.err"; fail "edit does not name SIG$sig"; }
	edited_in_memory
	cmp "$PA" "$W/partA.edited" || fail "SIG$sig changed part A"
done
[ "$(ls -A "$W/host1/secrets")" = restic ] || fail "edit left a file next to part A"

log "edit: without a directory in memory it stops before it opens the secret"
# In a mount namespace of its own, with a directory of the disk over /run
# and /dev/shm. A working directory that is itself in memory cannot show it.
mkdir -p "$W/disk"
case $(stat -f -c %T "$W/disk") in
tmpfs | ramfs)
	echo "skipped: $W is in memory"
	;;
*)
	gets() { grep -c 'op=get' "$W/host1-daemon.log" || true; }
	on_disk() { # arguments of edit...
		rm -f "$REPORT"
		VISUAL='' EDITOR="$W/editor" EDITOR_REPORT="$REPORT" EDITOR_DOES=true DISK="$W/disk" \
			ip netns exec host1 env -u XDG_RUNTIME_DIR unshare -m sh -c \
			'mount --bind "$DISK" /run && mount --bind "$DISK" /dev/shm && exec "$@"' sh \
			"$BIN/ergosumd" secret edit restic -file "$PA" -recovery "$(cat "$W/alice.pub")" \
			-config "$W/host1/ergosumd.yaml" -socket "$SOCK" "$@"
	}
	before=$(gets)
	if on_disk 2> "$W/edit.err"; then fail "edit wrote the secret to a disk"; fi
	grep -q -- '-tmpdir' "$W/edit.err" || { cat "$W/edit.err"; fail "edit does not point to -tmpdir"; }
	[ ! -e "$REPORT" ] || fail "the editor ran without a directory in memory"
	[ "$(gets)" = "$before" ] || fail "edit opened the secret before it stopped"
	# -tmpdir is taken as it is, with a warning.
	on_disk -tmpdir "$W/disk" 2> "$W/edit.err" || { cat "$W/edit.err"; fail "edit with -tmpdir"; }
	grep -q 'neither tmpfs nor ramfs' "$W/edit.err" || { cat "$W/edit.err"; fail "edit does not warn about a -tmpdir on a disk"; }
	read -r _ _ _ dir < "$REPORT" || fail "the editor did not run with -tmpdir"
	case $dir in "$W/disk"/*) ;; *) fail "the editor's file was in $dir, not below -tmpdir" ;; esac
	# Not "nothing in -tmpdir": mount leaves a directory of its own in what
	# lies over /run.
	[ ! -e "$dir" ] || fail "edit left $dir behind"
	cmp "$PA" "$W/partA.edited" || fail "edit without a directory in memory changed part A"
	;;
esac

# An instance allows an identity ten requests at once and then one per
# minute, and forgets the count when it starts. What follows has the
# requests it had before replace and edit were tried here.
for n in a b; do
	stop "$n"
	start "$n"
done

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
