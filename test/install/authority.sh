#!/bin/sh
# Runs in a container of test/install/run.sh: sets up an authority host
# with install.sh --authority from the release at $URL and checks what it
# did. Then the authority runs as set up, after the remaining steps of
# docs/authority.md, and an update to $NEXT_RELEASE replaces its binary
# without restarting it. T is the directory with install.sh and the test's
# release keys (default /t); RELEASE is the latest release.
set -eu

fail() { echo "FAIL: $*" >&2; exit 1; }
log() { printf '\n-- %s\n' "$*"; }
T=${T:-/t}

log "packages"
. "$(dirname "$0")/packages.sh"

install="sh $T/install.sh --url $URL"
owner_mode() { stat -c '%U %G %a' "$1"; }
# The words of the command have no spaces.
as_nobody() { su -s /bin/sh nobody -c "$*"; }
version_of() { "$1" version | awk 'NR == 1 {print $2}'; }
# authority_pid: the process of the authority, if one runs.
authority_pid() {
	for p in /proc/[0-9]*; do
		if [ "$(cat "$p/comm" 2>/dev/null)" = ergosum ]; then
			echo "${p#/proc/}"
			return 0
		fi
	done
	return 1
}
healthz() {
	if command -v curl >/dev/null; then
		curl -fsS http://127.0.0.1:7434/healthz
	else
		wget -qO- http://127.0.0.1:7434/healthz
	fi
}
service_files() { ls /etc/systemd/system/ergosum.service /etc/init.d/ergosum 2>/dev/null || true; }

log "refused runs change nothing"
if as_nobody $install --authority >/tmp/out 2>&1; then fail "installed as nobody"; fi
grep -q 'run as root, such as with sudo' /tmp/out || { cat /tmp/out; fail "no hint at root"; }
if $install --authority --anchor "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@https://192.0.2.10:7432" >/tmp/out 2>&1; then
	fail "installed with --authority and --anchor"
fi
grep -q 'are for a machine, not with --authority' /tmp/out || { cat /tmp/out; fail "--anchor with --authority not refused"; }
if $install --authority /tmp ergosumd >/tmp/out 2>&1; then fail "installed with --authority and a BINARY"; fi
grep -q 'takes no BINARY' /tmp/out || { cat /tmp/out; fail "BINARY with --authority not refused"; }
# The authority's binary without DIR, as one might try it.
if $install ergosum >/tmp/out 2>&1; then fail "took ergosum for a directory"; fi
grep -q 'ergosum is no directory with release files; .*--authority downloads' /tmp/out ||
	{ cat /tmp/out; fail "no hint at --authority"; }
if $install --authority --signers "$T/other-signers" >/tmp/out 2>&1; then
	fail "installed a release signed with another key"
fi
grep -q 'does not verify' /tmp/out || { cat /tmp/out; fail "no signature error"; }
[ ! -e /usr/bin/ergosum ] || fail "refused runs installed ergosum"
! id ergosum-authority >/dev/null 2>&1 || fail "refused runs created the user ergosum-authority"
[ ! -e /etc/ergosum ] || fail "refused runs left /etc/ergosum"
[ ! -e /var/lib/ergosum-authority ] || fail "refused runs left the state directory"
[ -z "$(service_files)" ] || fail "refused runs installed $(service_files)"

log "new authority"
$install --authority >/tmp/out 2>&1 || { cat /tmp/out; fail "installation"; }
cat /tmp/out
[ "$(version_of /usr/bin/ergosum)" = "$RELEASE" ] || fail "ergosum $RELEASE not installed"
cmp -s /etc/ergosum/release-signers "$T/release-signers" || fail "release keys not kept"
grep -q '^install.sh: user ergosum-authority created$' /tmp/out || fail "user not reported"
# A group of its own and no other: not ergosum-token, whose members read
# a daemon's token on the same host.
[ "$(id -nG ergosum-authority)" = ergosum-authority ] || fail "ergosum-authority is in $(id -nG ergosum-authority)"
case $(grep '^ergosum-authority:' /etc/passwd | cut -d: -f7) in
*/nologin) ;;
*) fail "ergosum-authority has a login shell: $(grep '^ergosum-authority:' /etc/passwd)" ;;
esac
[ "$(owner_mode /var/lib/ergosum-authority)" = "ergosum-authority ergosum-authority 700" ] ||
	fail "state directory is $(owner_mode /var/lib/ergosum-authority)"
[ "$(owner_mode /etc/ergosum)" = "root root 755" ] || fail "/etc/ergosum is $(owner_mode /etc/ergosum)"
if command -v systemctl >/dev/null; then
	grep -q '^ExecStart=/usr/bin/ergosum serve --config /etc/ergosum/serve.yaml$' /etc/systemd/system/ergosum.service ||
		fail "no systemd unit"
	grep -q '^u ergosum-authority ' /etc/sysusers.d/ergosum-authority.conf || fail "no sysusers file"
	[ ! -e /etc/systemd/system/multi-user.target.wants/ergosum.service ] || fail "unit enabled"
	grep -q 'then: systemctl enable --now ergosum$' /tmp/out || fail "no hint how to start the unit"
elif [ -x /sbin/openrc-run ]; then
	[ -x /etc/init.d/ergosum ] || fail "no OpenRC script"
	grep -q '^command_user="ergosum-authority:ergosum-authority"$' /etc/init.d/ergosum || fail "not the authority's OpenRC script"
	! rc-update show default 2>/dev/null | grep -q ergosum || fail "OpenRC script added to a runlevel"
	grep -q 'then: rc-update add ergosum default && rc-service ergosum start$' /tmp/out ||
		fail "no hint how to start the OpenRC service"
else
	[ -z "$(service_files)" ] || fail "service installed without a service manager"
	grep -q 'then: run "ergosum serve" as the user ergosum-authority (no systemd or OpenRC)$' /tmp/out || fail "no note that there is no service manager"
fi
grep -q 'the authority is not started: it needs its signing key and /etc/ergosum/serve.yaml' /tmp/out ||
	fail "no note on what the authority needs"
! authority_pid >/dev/null || fail "authority started"

log "the authority runs as set up"
# The remaining steps of docs/authority.md, with a key without a passphrase.
ergosum keygen -out /etc/ergosum/signing.key >/tmp/keygen
chgrp ergosum-authority /etc/ergosum/signing.key
chmod 0640 /etc/ergosum/signing.key
ssh-keygen -q -t ed25519 -N "" -C alice@example.com -f /tmp/alice
cat >/etc/ergosum/serve.yaml <<EOF
instance: authority-a
trust_domain: example.com
issuer: https://ergosum.example.com
signing_key: /etc/ergosum/signing.key
listen: "127.0.0.1:7432"
registry:
  admins:
    alice: "$(cat /tmp/alice.pub)"
  approvals:
    binding.set:     { threshold: 1, keys: [alice] }
    binding.revoked: { threshold: 1, keys: [alice] }
EOF
# No service manager runs in a container: this starts the authority the way
# its unit would, with the defaults for the journal and the control socket
# in the state directory.
cmd="/usr/bin/ergosum serve --config /etc/ergosum/serve.yaml --log-format text"
if command -v runuser >/dev/null; then
	runuser -u ergosum-authority -- $cmd >/tmp/authority.log 2>&1 &
else
	su -s /bin/sh ergosum-authority -c "$cmd >/tmp/authority.log 2>&1 &"
fi
n=0
until [ "$(healthz 2>/dev/null)" = ok ]; do
	n=$((n + 1))
	[ "$n" -lt 30 ] || { cat /tmp/authority.log; fail "authority not healthy"; }
	sleep 1
done
pid=$(authority_pid) || fail "no authority process"
[ "$(stat -c %U "/proc/$pid")" = ergosum-authority ] || fail "authority does not run as ergosum-authority"
[ -S /var/lib/ergosum-authority/control.sock ] || fail "no control socket in the state directory"

log "second run keeps everything"
before=$(cat /etc/ergosum/serve.yaml /etc/ergosum/signing.key $(service_files) | sha256sum)
$install --authority >/tmp/out 2>&1 || { cat /tmp/out; fail "second run"; }
cat /tmp/out
grep -q "ergosum $RELEASE is already installed" /tmp/out || fail "binary installed again"
if grep -q 'user ergosum-authority created\|ergosum.service installed\|init.d/ergosum installed\|not started' /tmp/out; then
	fail "set up again"
fi
[ "$(cat /etc/ergosum/serve.yaml /etc/ergosum/signing.key $(service_files) | sha256sum)" = "$before" ] ||
	fail "configuration, key or service changed"
[ "$(authority_pid)" = "$pid" ] || fail "authority restarted"

log "update to $NEXT_RELEASE"
$install --authority --version "$NEXT_RELEASE" >/tmp/out 2>&1 || { cat /tmp/out; fail "update"; }
cat /tmp/out
[ "$(version_of /usr/bin/ergosum)" = "$NEXT_RELEASE" ] || fail "ergosum $NEXT_RELEASE not installed"
[ "$(version_of /usr/bin/ergosum.old)" = "$RELEASE" ] || fail "no way back to $RELEASE"
grep -q 'the authority runs the new binary after a restart' /tmp/out || fail "no hint at the restart"
[ "$(authority_pid)" = "$pid" ] || fail "authority restarted by the update"
[ "$(healthz)" = ok ] || fail "authority not healthy after the update"
if $install --authority --version "$RELEASE" >/tmp/out 2>&1; then fail "installed the older $RELEASE"; fi
grep -q 'older than the installed' /tmp/out || { cat /tmp/out; fail "older version not refused"; }
echo "ok"
