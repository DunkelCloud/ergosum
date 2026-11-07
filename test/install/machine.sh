#!/bin/sh
# Runs on a machine of test/install/run.sh (a container) or of
# test/install/macos.sh (a Mac): prepares it, sets it up with install.sh
# from the release at $URL and checks what it did. T is the directory with
# install.sh and the test's release keys (default /t). ANCHOR is the
# authority to name; by default one that does not answer.
set -eu

fail() { echo "FAIL: $*" >&2; exit 1; }
log() { printf '\n-- %s\n' "$*"; }
T=${T:-/t}

if [ "$(uname -s)" = Darwin ]; then
	# A Mac whose launchd runs the daemon, with root's PATH: no GNU tools.
	PATH=/usr/bin:/bin:/usr/sbin:/sbin
	export PATH
	bindir=/usr/local/bin svc_user=_ergosum state=/var/db/ergosum/state
	daemon_log=/var/log/ergosum/ergosumd.log
	logged_identity='"identity":"host1.example.com"'
	running() { pgrep -x ergosumd >/dev/null; }
	owner_mode() { stat -f '%Su %Sg %Lp' "$1"; }
	sum() { shasum -a 256; }
	as_nobody() { sudo -u nobody "$@"; }
else
	bindir=/usr/bin svc_user=ergosum state=/var/lib/ergosum
	daemon_log=/tmp/ergosumd.log
	logged_identity='identity=host1.example.com'
	running() {
		for p in /proc/[0-9]*; do
			[ "$(cat "$p/comm" 2>/dev/null)" = ergosumd ] && return 0
		done
		return 1
	}
	owner_mode() { stat -c '%U %G %a' "$1"; }
	sum() { sha256sum; }
	# The words of the command have no spaces.
	as_nobody() { su -s /bin/sh nobody -c "$*"; }

	log "packages"
	. "$(dirname "$0")/packages.sh"

	# No service manager runs in a container: this starts the daemon the
	# way its unit would, after stopping one that runs.
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
fi

install="sh $T/install.sh --url $URL"
anchor=${ANCHOR:-"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@https://192.0.2.10:7432,https://198.51.100.10:7432"}

log "refused runs change nothing"
if as_nobody $install --anchor "$anchor" >/tmp/out 2>&1; then fail "installed as nobody"; fi
grep -q 'run as root, such as with sudo' /tmp/out || { cat /tmp/out; fail "no hint at root"; }
! grep -q 'downloading' /tmp/out || { cat /tmp/out; fail "downloaded before the check for root"; }
if $install >/tmp/out 2>&1; then fail "installed without --anchor"; fi
grep -q 'needs --anchor' /tmp/out || { cat /tmp/out; fail "no hint at --anchor"; }
if $install --anchor nonsense >/tmp/out 2>&1; then fail "installed with a bad anchor"; fi
grep -q 'KEY@URL' /tmp/out || { cat /tmp/out; fail "no hint at the anchor's form"; }
for key in "SHA256:$(printf '%064d' 0)" "SHA256:AAAA" "SHA256:$(printf '%042d' 0)-"; do
	if $install --anchor "$key@https://192.0.2.10:7432" >/tmp/out 2>&1; then fail "installed with the key $key"; fi
	grep -q "$key in --anchor is no key fingerprint" /tmp/out || { cat /tmp/out; fail "key $key not refused"; }
done
if $install --signers "$T/other-signers" --anchor "$anchor" >/tmp/out 2>&1; then
	fail "installed a release signed with another key"
fi
grep -q 'does not verify' /tmp/out || { cat /tmp/out; fail "no signature error"; }
if $install --identity host1 --anchor "$anchor" >/tmp/out 2>&1; then fail "installed with a short identity"; fi
grep -q 'identity "host1" from --identity is not a full DNS name' /tmp/out || { cat /tmp/out; fail "short identity not refused"; }
if $install --identity host1.example.com --domain example.org --anchor "$anchor" >/tmp/out 2>&1; then
	fail "installed with --identity and --domain"
fi
grep -q 'exclude each other' /tmp/out || { cat /tmp/out; fail "--identity with --domain not refused"; }
# A machine whose hostname -f gives no full name, localhost or the name of
# a Mac without a host name of its own.
mkdir -p /tmp/fake
printf '#!/bin/sh\necho "$FAKE_HOST"\n' >/tmp/fake/hostname
chmod +x /tmp/fake/hostname
if FAKE_HOST=host1 PATH=/tmp/fake:$PATH $install --anchor "$anchor" >/tmp/out 2>&1; then
	fail "installed with a short host name"
fi
grep -q 'identity "host1" from hostname -f .*--domain' /tmp/out || { cat /tmp/out; fail "short host name not refused with a hint at --domain"; }
if FAKE_HOST=localhost.localdomain PATH=/tmp/fake:$PATH $install --anchor "$anchor" >/tmp/out 2>&1; then
	fail "installed as localhost"
fi
grep -q 'names no machine' /tmp/out || { cat /tmp/out; fail "localhost not refused"; }
if FAKE_HOST=Hosts-MacBook-Pro.local PATH=/tmp/fake:$PATH $install --anchor "$anchor" >/tmp/out 2>&1; then
	fail "installed with a .local name"
fi
grep -q 'identity "hosts-macbook-pro.local" from hostname -f is a multicast DNS name' /tmp/out ||
	{ cat /tmp/out; fail ".local name not refused"; }
[ ! -e /etc/ergosum ] || fail "refused runs left /etc/ergosum"
[ ! -e "$bindir/ergosumd" ] || fail "refused runs installed ergosumd"
! id "$svc_user" >/dev/null 2>&1 || fail "refused runs created the user $svc_user"

log "configuration that ergosumd refuses"
# A URL without a port passes the script's check of the anchor's form;
# ergosumd refuses it after the binary and the user are in place, which a
# second run keeps.
if $install --anchor "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@https://192.0.2.10" >/tmp/out 2>&1; then
	fail "installed with a URL without a port"
fi
grep -q 'refuses the configuration: .*needs a port' /tmp/out || { cat /tmp/out; fail "URL without a port not refused by ergosumd"; }
[ ! -e /etc/ergosum/ergosumd.yaml ] || fail "configuration left by a refused run"
[ ! -e /etc/ergosum/ergosumd.yaml.new ] || fail "draft configuration left by a refused run"
! running || fail "daemon started by a refused run"
if [ -n "${ANCHOR:-}" ]; then
	# An authority that answers with another key than the one in --anchor.
	if $install --anchor "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB@${ANCHOR#*@}" >/tmp/out 2>&1; then
		fail "installed with another key than the authority's"
	fi
	grep -q 'does not present the key in --anchor' /tmp/out || { cat /tmp/out; fail "another key than the authority's not refused"; }
	grep -qF "presents ${ANCHOR%%@*}, not the configured SHA256:BBBB" /tmp/out || { cat /tmp/out; fail "the authority's key not named"; }
	[ ! -e /etc/ergosum/ergosumd.yaml ] || fail "configuration left by a run with another key"
	! running || fail "daemon started by a run with another key"
fi
rm -f "$bindir/ergosumd"

log "new machine"
$install --version "$RELEASE" --anchor "$anchor" >/tmp/out 2>&1 || { cat /tmp/out; fail "first installation"; }
cat /tmp/out
[ "$("$bindir/ergosumd" version | awk '{print $2}')" = "$RELEASE" ] || fail "ergosumd $RELEASE not installed"
cmp -s /etc/ergosum/release-signers "$T/release-signers" || fail "release keys not kept"
[ "$(id -gn "$svc_user")" = "$svc_user" ] || fail "$svc_user's group is $(id -gn "$svc_user")"
id -nG "$svc_user" | tr ' ' '\n' | grep -qx ergosum-token || fail "$svc_user not in ergosum-token"
[ "$(owner_mode "$state")" = "$svc_user $svc_user 700" ] ||
	fail "state directory is $(owner_mode "$state")"
grep -qx 'identity: host1.example.com' /etc/ergosum/ergosumd.yaml || fail "identity not from hostname -f"
if [ -n "${ANCHOR:-}" ]; then
	grep -q '^install.sh: authority .*, as configured$' /tmp/out || fail "the authority's key not checked"
else
	grep -q '^install.sh: authority https://192.0.2.10:7432: not reached' /tmp/out || fail "unreachable authority not reported"
fi
fp=$(grep '^key ' /tmp/out | awk '{print $2}')
[ -n "$fp" ] || fail "no binding request printed"
grep -q '^identity host1.example.com$' /tmp/out || fail "request names another identity"
if [ "$(uname -s)" = Darwin ]; then
	[ "$(id -u _ergosum)" -lt 500 ] || fail "_ergosum has ID $(id -u _ergosum), not one of a system account"
	dscl . -read /Users/_ergosum UserShell | grep -q '/usr/bin/false$' || fail "_ergosum has a login shell"
	[ "$(owner_mode /var/db/ergosum)" = "_ergosum _ergosum 755" ] ||
		fail "token directory is $(owner_mode /var/db/ergosum)"
	plist=/Library/LaunchDaemons/io.github.dunkelcloud.ergosumd.plist
	[ "$(owner_mode "$plist")" = "root wheel 644" ] || fail "launchd job is $(owner_mode "$plist")"
	plutil -lint "$plist" >/dev/null || fail "launchd job does not parse"
fi
if command -v systemctl >/dev/null; then
	grep -q '^ExecStart=/usr/bin/ergosumd run' /etc/systemd/system/ergosumd.service || fail "no systemd unit"
	grep -q '^u ergosum ' /etc/sysusers.d/ergosum.conf || fail "no sysusers file"
fi
if [ -x /sbin/openrc-run ]; then
	[ -x /etc/init.d/ergosumd ] || fail "no OpenRC script"
fi
sleep 2
running || { cat "$daemon_log"; fail "daemon not running"; }
if [ "$(uname -s)" = Darwin ]; then
	[ "$(ps -o uid= -p "$(pgrep -x ergosumd)" | tr -d ' ')" = "$(id -u _ergosum)" ] || fail "daemon does not run as _ergosum"
fi
grep -qF "$logged_identity" "$daemon_log" || { cat "$daemon_log"; fail "daemon log names no identity"; }

log "second run keeps everything"
before=$(cat /etc/ergosum/ergosumd.yaml "$state/identity.key" | sum)
$install --anchor "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB@https://192.0.2.99:7432" >/tmp/out 2>&1 ||
	{ cat /tmp/out; fail "second run"; }
cat /tmp/out
grep -q 'already installed' /tmp/out || fail "binary installed again"
grep -q 'exists and stays' /tmp/out || fail "no note that the configuration stays"
[ "$(cat /etc/ergosum/ergosumd.yaml "$state/identity.key" | sum)" = "$before" ] || fail "configuration or key changed"
grep -q "^key $fp\$" /tmp/out || fail "request with another key"
sleep 2
running || fail "daemon not running after the second run"

log "--domain: the host name in that domain"
# The machine's host name is host1.example.com; another configuration
# file makes this machine new again, except for its binary, users and key.
$install --domain Example.ORG --config /tmp/domain.yaml --no-restart --anchor "$anchor" >/tmp/out 2>&1 ||
	{ cat /tmp/out; fail "run with --domain"; }
grep -qx 'identity: host1.example.org' /tmp/domain.yaml || { cat /tmp/out; fail "identity not from the host name and --domain"; }
grep -q '^identity host1.example.org$' /tmp/out || { cat /tmp/out; fail "request names another identity"; }
echo "ok"
