#!/bin/sh
# Runs in a container of test/install/run.sh: prepares the distribution,
# sets the machine up with install.sh from the release at $URL and checks
# what it did.
set -eu

fail() { echo "FAIL: $*" >&2; exit 1; }
log() { printf '\n-- %s\n' "$*"; }
running() { # the daemon runs
	for p in /proc/[0-9]*; do
		[ "$(cat "$p/comm" 2>/dev/null)" = ergosumd ] && return 0
	done
	return 1
}

log "packages"
if command -v apk >/dev/null; then
	apk add -q --no-cache openssh-keygen openrc
else
	export DEBIAN_FRONTEND=noninteractive
	. /etc/os-release
	pkgs="openssh-client wget"
	[ "$ID" = ubuntu ] && pkgs="openssh-client curl systemd"
	apt-get update -qq
	# shellcheck disable=SC2086 # a list of packages
	apt-get install -qq -y --no-install-recommends $pkgs >/dev/null
fi

# No service manager runs in a container: this starts the daemon the way
# its unit would, after stopping one that runs.
cat >/tmp/start <<'EOF'
for p in /proc/[0-9]*; do
	[ "$(cat "$p/comm" 2>/dev/null)" = ergosumd ] && kill "${p#/proc/}"
done
mkdir -p /run/ergosum
chown ergosum:ergosum /run/ergosum
cmd="/usr/bin/ergosumd run --config /etc/ergosum/ergosumd.yaml --log-format text"
if command -v runuser >/dev/null; then
	runuser -u ergosum -- $cmd >>/tmp/ergosumd.log 2>&1 &
else
	su -s /bin/sh ergosum -c "$cmd >>/tmp/ergosumd.log 2>&1 &"
fi
EOF
export RESTART_CMD="sh /tmp/start"

install="sh /t/install.sh --url $URL"
anchor="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@https://192.0.2.10:7432,https://198.51.100.10:7432"

log "refused runs change nothing"
if $install >/tmp/out 2>&1; then fail "installed without --anchor"; fi
grep -q 'needs --anchor' /tmp/out || { cat /tmp/out; fail "no hint at --anchor"; }
if $install --anchor nonsense >/tmp/out 2>&1; then fail "installed with a bad anchor"; fi
grep -q 'KEY@URL' /tmp/out || { cat /tmp/out; fail "no hint at the anchor's form"; }
if $install --signers /t/other-signers --anchor "$anchor" >/tmp/out 2>&1; then
	fail "installed a release signed with another key"
fi
grep -q 'does not verify' /tmp/out || { cat /tmp/out; fail "no signature error"; }
if $install --identity host1 --anchor "$anchor" >/tmp/out 2>&1; then fail "installed with a short identity"; fi
grep -q 'refuses the configuration' /tmp/out || { cat /tmp/out; fail "short identity not refused by ergosumd"; }
[ ! -e /etc/ergosum/ergosumd.yaml ] || fail "configuration left by a refused run"
[ ! -e /etc/ergosum/ergosumd.yaml.new ] || fail "draft configuration left by a refused run"
! running || fail "daemon started by a refused run"
# The short identity got as far as the binary and the user, which a second
# run keeps.
rm -f /usr/bin/ergosumd

log "new machine"
$install --version "$RELEASE" --anchor "$anchor" >/tmp/out 2>&1 || { cat /tmp/out; fail "first installation"; }
cat /tmp/out
[ "$(/usr/bin/ergosumd version | awk '{print $2}')" = "$RELEASE" ] || fail "ergosumd $RELEASE not installed"
cmp -s /etc/ergosum/release-signers /t/release-signers || fail "release keys not kept"
[ "$(id -gn ergosum)" = ergosum ] || fail "ergosum's group is $(id -gn ergosum)"
id -nG ergosum | tr ' ' '\n' | grep -qx ergosum-token || fail "ergosum not in ergosum-token"
[ "$(stat -c '%U %G %a' /var/lib/ergosum)" = "ergosum ergosum 700" ] ||
	fail "state directory is $(stat -c '%U %G %a' /var/lib/ergosum)"
grep -qx 'identity: host1.example.com' /etc/ergosum/ergosumd.yaml || fail "identity not from hostname -f"
fp=$(grep '^key ' /tmp/out | awk '{print $2}')
[ -n "$fp" ] || fail "no binding request printed"
grep -q '^identity host1.example.com$' /tmp/out || fail "request names another identity"
if command -v systemctl >/dev/null; then
	grep -q '^ExecStart=/usr/bin/ergosumd run' /etc/systemd/system/ergosumd.service || fail "no systemd unit"
	grep -q '^u ergosum ' /etc/sysusers.d/ergosum.conf || fail "no sysusers file"
fi
if [ -x /sbin/openrc-run ]; then
	[ -x /etc/init.d/ergosumd ] || fail "no OpenRC script"
fi
sleep 2
running || { cat /tmp/ergosumd.log; fail "daemon not running"; }
grep -q 'identity=host1.example.com' /tmp/ergosumd.log || { cat /tmp/ergosumd.log; fail "daemon log names no identity"; }

log "second run keeps everything"
sum=$(cat /etc/ergosum/ergosumd.yaml /var/lib/ergosum/* | sha256sum)
$install --anchor "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB@https://192.0.2.99:7432" >/tmp/out 2>&1 ||
	{ cat /tmp/out; fail "second run"; }
cat /tmp/out
grep -q 'already installed' /tmp/out || fail "binary installed again"
grep -q 'exists and stays' /tmp/out || fail "no note that the configuration stays"
[ "$(cat /etc/ergosum/ergosumd.yaml /var/lib/ergosum/* | sha256sum)" = "$sum" ] || fail "configuration or key changed"
grep -q "^key $fp\$" /tmp/out || fail "request with another key"
sleep 2
running || fail "daemon not running after the second run"
echo "ok"
