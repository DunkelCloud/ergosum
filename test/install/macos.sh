#!/usr/bin/env bash
# A Mac set up by deploy/install.sh, on a CI runner that is thrown away
# afterwards: the script changes the machine (users, launchd, host name).
#
# An authority runs on the same Mac. test/install/machine.sh checks the
# new machine with the authority as anchor: refused runs that change
# nothing, the user _ergosum and the group ergosum-token in the directory
# service, the directories, the launchd job and the daemon running as
# _ergosum. Then the authority records a binding with a net check of the
# Mac's network, and the daemon writes its token, group-owned by
# ergosum-token, which tests the group lookup of a build without cgo.
# Last, install.sh updates the daemon to the newer release through
# launchctl and waits for a new token, and refuses the older one.
#
# Needs root, curl, jq and python3. BIN holds ergosum and ergosumd, NEXT a
# newer ergosumd, both native builds with release versions (see
# .github/workflows/ci.yml). Written for bash 3.2, macOS's own.
# Usage: sudo env PATH="$PATH" BIN=dist NEXT=dist-next test/install/macos.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
NEXT=${NEXT:?set NEXT to a build of ergosumd newer than BIN}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d /tmp/ergosum-macos.XXXXXX)
LABEL=io.github.dunkelcloud.ergosumd
PIDS=

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
	set +e
	launchctl bootout "system/$LABEL" 2>/dev/null
	for p in $PIDS; do kill "$p" 2>/dev/null; done
	if [ "${KEEP:-}" = "" ]; then rm -rf "$W"; fi
}
trap cleanup EXIT

# On failure: what launchd and the daemon say.
diagnose() {
	set +e
	launchctl print "system/$LABEL" | head -40
	ls -la /var/db/ergosum /var/log/ergosum
	tail -20 /var/log/ergosum/ergosumd.log
	tail -20 "$W/authority.log"
}

version=$("$BIN/ergosumd" version | awk '{print $2}')
next=$("$NEXT/ergosumd" version | awk '{print $2}')
arch=$(uname -m | sed 's/x86_64/amd64/')

log "releases $version and $next, signed with a test key"
"$ROOT/test/install/release.sh" "$W" darwin "$arch" "$BIN" "$NEXT"
(cd "$W/www" && exec python3 -m http.server 8000 --bind 127.0.0.1) >"$W/web.log" 2>&1 &
PIDS="$PIDS $!"
URL=http://127.0.0.1:8000
for _ in $(seq 50); do curl -fs -o /dev/null "$URL/latest/download/SHA256SUMS" && break; sleep 0.2; done
curl -fs -o /dev/null "$URL/latest/download/SHA256SUMS" || fail "web server not up"

log "host name host1.example.com"
scutil --set HostName host1.example.com
hostname host1.example.com
[ "$(hostname -f)" = host1.example.com ] || fail "host name is $(hostname -f)"

log "authority on this Mac"
iface=$(route -n get default | awk '/interface:/ {print $2}')
read -r ip mask < <(ifconfig "$iface" | awk '$1 == "inet" {print $2, $4; exit}')
net=$(python3 -c '
import ipaddress, sys
print(ipaddress.ip_interface(sys.argv[1] + "/" + str(bin(int(sys.argv[2], 16)).count("1"))).network)
' "$ip" "$mask")
echo "$iface: $ip in $net"
"$BIN/ergosum" keygen -out "$W/signing.key" >"$W/keygen.txt"
AUTH_FP=$(awk '/^fingerprint:/ {print $2}' "$W/keygen.txt")
[ -n "$AUTH_FP" ] || fail "no fingerprint from keygen"
ssh-keygen -q -t ed25519 -N "" -C alice@example.com -f "$W/alice"
mkdir -p "$W/authority"
cat >"$W/serve.yaml" <<EOF
instance: authority-a
trust_domain: example.com
issuer: https://ergosum.example.com
signing_key: $W/signing.key
journal: $W/authority/journal.db
control_socket: $W/authority/control.sock
listen: "$ip:7432"
ops_listen: "127.0.0.1:7434"
callbacks:
  networks:
    - cidr: $net
      source: $ip
registry:
  admins:
    alice: "$(cat "$W/alice.pub")"
  approvals:
    binding.set: {threshold: 1, keys: [alice]}
    binding.revoked: {threshold: 1, keys: [alice]}
EOF
"$BIN/ergosum" serve --config "$W/serve.yaml" --log-format text >"$W/authority.log" 2>&1 &
PIDS="$PIDS $!"
ops() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:7434$1" || true; }
for _ in $(seq 50); do [ "$(ops /healthz)" = 200 ] && break; sleep 0.2; done
[ "$(ops /healthz)" = 200 ] || { cat "$W/authority.log"; fail "authority not up"; }

log "new machine (test/install/machine.sh)"
T=$W URL=$URL RELEASE=$version ANCHOR="$AUTH_FP@https://$ip:7432" sh "$ROOT/test/install/machine.sh" ||
	{ diagnose; fail "new machine"; }

log "binding with a net check of $net"
fp=$(sudo -u _ergosum /usr/local/bin/ergosumd fingerprint -config /etc/ergosum/ergosumd.yaml)
printf 'ergosum binding v1\nkind binding.set\ntrust-domain example.com\nidentity host1.example.com\nepoch 1\nkey %s\ncheck net %s\n' "$fp" "$net" >"$W/event.txt"
ssh-keygen -q -Y sign -f "$W/alice" -n ergosum-binding "$W/event.txt"
jq -n --arg key "$fp" --arg net "$net" --rawfile sig "$W/event.txt.sig" '{
	v: 1, kind: "binding.set", trust_domain: "example.com", identity: "host1.example.com",
	epoch: 1, key: $key, checks: [{type: "net", target: $net}], signatures: [$sig]
}' >"$W/event.json"
code=$(curl -sk -o "$W/bind.out" -w '%{http_code}' -H 'Content-Type: application/json' \
	--data @"$W/event.json" "https://$ip:7432/v1/bindings")
[ "$code" = 201 ] || { cat "$W/bind.out"; fail "binding write returned $code"; }

log "token"
# Ask now instead of after the daemon's back-off.
launchctl kickstart -k "system/$LABEL"
token=/var/db/ergosum/token
for _ in $(seq 100); do [ -s "$token" ] && break; sleep 0.3; done
[ -s "$token" ] || { diagnose; fail "no token"; }
[ "$(stat -f '%Su %Sg %Lp' "$token")" = "_ergosum ergosum-token 640" ] ||
	{ diagnose; fail "token is $(stat -f '%Su %Sg %Lp' "$token")"; }
if grep -q 'token group not found' /var/log/ergosum/ergosumd.log; then fail "daemon did not find ergosum-token"; fi
sub=$(python3 -c '
import base64, json, sys
p = open(sys.argv[1]).read().split(".")[1]
print(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))["sub"])
' "$token")
[ "$sub" = spiffe://example.com/host/host1.example.com ] || fail "token for $sub"
ls -l /var/log/ergosum

log "update to $next"
# root's PATH, as in machine.sh: no GNU tools.
base_path="env PATH=/usr/bin:/bin:/usr/sbin:/sbin"
$base_path sh "$W/install.sh" --url "$URL" --version "$next" >"$W/out" 2>&1 || { cat "$W/out"; diagnose; fail "update"; }
cat "$W/out"
grep -q "ergosumd $next is running and has a new token" "$W/out" || fail "no new token after the update"
[ "$(/usr/local/bin/ergosumd version | awk '{print $2}')" = "$next" ] || fail "ergosumd $next not installed"
[ "$(/usr/local/bin/ergosumd.old version | awk '{print $2}')" = "$version" ] || fail "no way back to $version"
if $base_path sh "$W/install.sh" --url "$URL" --version "$version" >"$W/out" 2>&1; then fail "installed the older $version"; fi
grep -q 'older than the installed' "$W/out" || { cat "$W/out"; fail "older version not refused"; }

log "PASS"
