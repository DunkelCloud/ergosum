#!/bin/sh
# Installs ergosum binaries from a downloaded release, as root on the
# target machine:
#
#   deploy/install.sh [options] DIR [BINARY...]
#
# DIR holds SHA256SUMS, SHA256SUMS.sig and the release files. BINARY is
# ergosumd (the default) or ergosum. The script
#
#   - checks the signature over SHA256SUMS against the release keys
#     (/etc/ergosum/release-signers, from the repository) and the checksum
#     of each file it installs;
#   - refuses a version older than the installed one;
#   - keeps the installed binary as BINARY.old and replaces it atomically;
#   - restarts ergosumd and waits for a new token. Without one in time it
#     puts the old binary back and restarts again.
#
# An authority (ergosum) is not restarted: after a restart it is sealed.
# Restart and unseal it by hand; BINARY.old stays for the way back.
#
# Options:
#   --allow-downgrade   install an older version
#   --no-restart        replace the binaries only
#   --wait SECONDS      how long to wait for a new token (default 120)
#   --signers FILE      release keys (default /etc/ergosum/release-signers)
#   --config FILE       daemon configuration, for the token and metrics
#                       files (default /etc/ergosum/ergosumd.yaml)
#
# BINDIR (default /usr/bin) and RESTART_CMD (a shell command that restarts
# ergosumd; default systemd or OpenRC) serve other layouts and tests.
set -eu

BINDIR=${BINDIR:-/usr/bin}
signers=/etc/ergosum/release-signers
config=/etc/ergosum/ergosumd.yaml
wait=120
downgrade=
restart=yes

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--allow-downgrade) downgrade=yes ;;
	--no-restart) restart= ;;
	--wait) wait=${2:?--wait needs seconds}; shift ;;
	--signers) signers=${2:?--signers needs a file}; shift ;;
	--config) config=${2:?--config needs a file}; shift ;;
	--) shift; break ;;
	-*) die "unknown option $1" ;;
	*) break ;;
	esac
	shift
done
dir=${1:?usage: install.sh [options] DIR [BINARY...]}
shift
[ $# -gt 0 ] || set -- ergosumd
for b in "$@"; do
	case $b in
	ergosumd | ergosum) ;;
	*) die "unknown binary $b (ergosumd or ergosum)" ;;
	esac
done

[ "$(uname -s)" = Linux ] || die "Linux only"
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
command -v ssh-keygen >/dev/null || die "ssh-keygen (OpenSSH 8.1 or later) is needed to check the signature"
[ -r "$signers" ] || die "no release keys at $signers; copy release-signers from the repository there"

# The signature covers SHA256SUMS, the checksums cover the files.
out=$(ssh-keygen -Y verify -f "$signers" -I release -n ergosum-release \
	-s "$dir/SHA256SUMS.sig" <"$dir/SHA256SUMS" 2>&1) ||
	die "signature over $dir/SHA256SUMS does not verify against $signers: $out"
say "signature over SHA256SUMS verified"

semver='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
is_semver() { printf '%s\n' "$1" | grep -Eq "$semver"; }

# newer A B: A is a higher version than B. A release sorts after its
# pre-releases; pre-releases compare as strings (rc.1 to rc.9). sh has no
# local variables, hence the prefix.
newer() {
	nv_a=${1#v} nv_b=${2#v}
	nv_ac=${nv_a%%-*} nv_bc=${nv_b%%-*}
	nv_ap='' nv_bp=''
	[ "$nv_ac" = "$nv_a" ] || nv_ap=${nv_a#*-}
	[ "$nv_bc" = "$nv_b" ] || nv_bp=${nv_b#*-}
	IFS=. read -r nv_a1 nv_a2 nv_a3 <<EOF
$nv_ac
EOF
	IFS=. read -r nv_b1 nv_b2 nv_b3 <<EOF
$nv_bc
EOF
	for nv_p in "$nv_a1 $nv_b1" "$nv_a2 $nv_b2" "$nv_a3 $nv_b3"; do
		# shellcheck disable=SC2086 # two numbers, split on purpose
		set -- $nv_p
		[ "$1" -gt "$2" ] && return 0
		[ "$1" -lt "$2" ] && return 1
	done
	[ -z "$nv_ap" ] && [ -n "$nv_bp" ] && return 0
	[ -n "$nv_ap" ] && [ -z "$nv_bp" ] && return 1
	[ -n "$nv_ap" ] && [ "$nv_ap" != "$nv_bp" ] &&
		[ "$(printf '%s\n%s\n' "$nv_ap" "$nv_bp" | sort | tail -n 1)" = "$nv_ap" ] && return 0
	return 1
}

version_of() { "$1" version 2>/dev/null | awk 'NR == 1 {print $2}'; }

# Value of a top-level key in the daemon configuration, without quotes.
config_value() {
	[ -r "$config" ] || return 0
	sed -n "s/^$1:[[:space:]]*//p" "$config" | sed 's/[[:space:]]*#.*$//; s/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/' | head -n 1
}

restart_daemon() {
	if [ -n "${RESTART_CMD:-}" ]; then
		sh -c "$RESTART_CMD"
	elif [ -d /run/systemd/system ]; then
		systemctl restart ergosumd
	elif command -v rc-service >/dev/null; then
		rc-service ergosumd restart
	else
		die "no systemd or OpenRC; restart ergosumd by hand or set RESTART_CMD"
	fi
}

# fresh MARKER VERSION: a token newer than MARKER, and the new version in
# the metrics file if there is one.
fresh() {
	[ -f "$token" ] && [ "$token" -nt "$1" ] || return 1
	[ -z "$metrics" ] && return 0
	grep -q "^machine_identity_build_info{version=\"$2\"," "$metrics" 2>/dev/null
}

wait_fresh() {
	n=0
	while [ "$n" -lt "$wait" ]; do
		fresh "$1" "$2" && return 0
		sleep 1
		n=$((n + 1))
	done
	return 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
installed_daemon=
for b in "$@"; do
	file=$b-linux-$arch
	[ -f "$dir/$file" ] || die "$dir/$file is missing"
	want=$(awk -v f="$file" '$2 == f || $2 == "*" f {n++; h = $1} END {if (n == 1) print h}' "$dir/SHA256SUMS")
	[ -n "$want" ] || die "$file is not listed once in SHA256SUMS"
	# Checked on a private copy, so that the file cannot change between the
	# check and the installation.
	cp "$dir/$file" "$tmp/$b"
	got=$(sha256sum "$tmp/$b" | awk '{print $1}')
	[ "$got" = "$want" ] || die "$file does not match SHA256SUMS"
	chmod 0755 "$tmp/$b"

	new=$(version_of "$tmp/$b")
	is_semver "$new" || die "$file reports no release version (\"$new\")"
	cur=
	[ -x "$BINDIR/$b" ] && cur=$(version_of "$BINDIR/$b")
	if [ "$cur" = "$new" ]; then
		say "$b $new is already installed"
		continue
	fi
	if is_semver "$cur" && ! newer "$new" "$cur" && [ -z "$downgrade" ]; then
		die "$b $new is older than the installed $cur; use --allow-downgrade"
	fi

	if [ -e "$BINDIR/$b" ]; then
		cp -p "$BINDIR/$b" "$BINDIR/$b.old"
	fi
	cp "$tmp/$b" "$BINDIR/.$b.new"
	chmod 0755 "$BINDIR/.$b.new"
	mv -f "$BINDIR/.$b.new" "$BINDIR/$b"
	say "$b ${cur:-(none)} -> $new installed${cur:+, previous binary kept as $BINDIR/$b.old}"
	case $b in
	ergosum) say "restart the authority by hand and unseal it" ;;
	ergosumd) installed_daemon=$new installed_daemon_old=$cur ;;
	esac
done

[ -n "$installed_daemon" ] || exit 0
if [ -z "$restart" ]; then
	say "not restarted (--no-restart)"
	exit 0
fi

token=$(config_value token_file)
token=${token:-/run/ergosum/token}
metrics=$(config_value metrics_file)
marker=$tmp/marker
touch "$marker"
sleep 1 # a token written in the same second would not count as newer
restart_daemon || say "restarting ergosumd returned an error"
if wait_fresh "$marker" "$installed_daemon"; then
	say "ergosumd $installed_daemon is running and has a new token"
	exit 0
fi

say "no new token within ${wait}s; going back"
[ -e "$BINDIR/ergosumd.old" ] || die "no $BINDIR/ergosumd.old to go back to; ergosumd $installed_daemon stays"
mv -f "$BINDIR/ergosumd.old" "$BINDIR/ergosumd"
touch "$marker"
sleep 1
restart_daemon || say "restarting ergosumd returned an error"
if wait_fresh "$marker" "$installed_daemon_old"; then
	die "ergosumd $installed_daemon failed; $installed_daemon_old is back and has a new token"
fi
die "ergosumd $installed_daemon failed, and $installed_daemon_old has no new token either"
