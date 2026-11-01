#!/bin/sh
# Installs ergosum from a signed release, as root on the target machine:
#
#   install.sh [options] [DIR [BINARY...]]
#
# Without DIR the script downloads the release (the latest, or --version);
# with DIR it takes the release files from there. BINARY is ergosumd (the
# default) or ergosum. The script
#
#   - checks the signature over SHA256SUMS against the release keys and the
#     checksum of each file it uses. The keys come from
#     /etc/ergosum/release-signers; a machine without that file gets the
#     copy in this script there;
#   - refuses a version older than the installed one;
#   - keeps the installed binary as BINARY.old and replaces it atomically;
#   - restarts ergosumd and waits for a new token. Without one in time it
#     puts the old binary back and restarts again.
#
# A machine whose ergosumd has no token yet, a new one above all, gets
# what is missing of the users, the state directory, the service (systemd
# or OpenRC) and the configuration, which the script writes from --anchor
# and --identity. Then it starts ergosumd without waiting for a token and
# prints the binding request for the administrators. Once they have
# recorded the binding, the daemon receives its token on its own.
#
# An authority (ergosum) is not restarted: after a restart it is sealed.
# Restart and unseal it by hand; BINARY.old stays for the way back.
#
# Options:
#   --anchor KEY@URL[,URL...]
#                       a new machine's authority: its key fingerprint
#                       (printed by "ergosum keygen") and its URLs
#   --identity NAME     a new machine's identity (default: hostname -f)
#   --version VERSION   the release to download (default: the latest)
#   --url URL           where releases are downloaded from (default
#                       https://github.com/DunkelCloud/ergosum/releases)
#   --allow-downgrade   install an older version
#   --no-restart        replace the binaries only; on a machine without a
#                       token, do not start ergosumd either
#   --wait SECONDS      how long to wait for a new token (default 120)
#   --signers FILE      release keys (default /etc/ergosum/release-signers)
#   --config FILE       daemon configuration (default
#                       /etc/ergosum/ergosumd.yaml)
#
# BINDIR (default /usr/bin) and RESTART_CMD (a shell command that starts or
# restarts ergosumd; default systemd or OpenRC) serve other layouts and tests.
set -eu

BINDIR=${BINDIR:-/usr/bin}
signers=
config=/etc/ergosum/ergosumd.yaml
url=https://github.com/DunkelCloud/ergosum/releases
version=
anchor=
identity=
wait=120
downgrade=
restart=yes

# The release keys as of this script, the same as release-signers in the
# repository (a test in internal/release keeps them equal).
release_signers() {
	cat <<'EOF'
# Keys that sign ergosum releases, in the ALLOWED SIGNERS format of
# ssh-keygen(1). A release signs SHA256SUMS in the namespace
# ergosum-release; docs/releasing.md shows how to verify it.
#
# SHA256:xcJy5kiogfRmaX7n8ednlEIcxJUxQGiN1QJgXxhKeSc
release namespaces="ergosum-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICosjgD9nkaIHwTvmSi/TRreT78T/OLS6nEP4F8jUbj3 ergosum-release
EOF
}

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--anchor) anchor=${2:?--anchor needs KEY@URL}; shift ;;
	--identity) identity=${2:?--identity needs a name}; shift ;;
	--version) version=${2:?--version needs a version}; shift ;;
	--url) url=${2:?--url needs a URL}; shift ;;
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
dir=
if [ $# -gt 0 ]; then
	dir=$1
	shift
	[ -z "$version" ] || die "--version is for a download; DIR is given"
fi
[ $# -gt 0 ] || set -- ergosumd
daemon=
for b in "$@"; do
	case $b in
	ergosumd) daemon=yes ;;
	ergosum) ;;
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

# Value of a top-level key in the daemon configuration, without quotes.
config_value() {
	[ -r "$config" ] || return 0
	sed -n "s/^$1:[[:space:]]*//p" "$config" | sed 's/[[:space:]]*#.*$//; s/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/' | head -n 1
}

token=$(config_value token_file)
token=${token:-/run/ergosum/token}
metrics=$(config_value metrics_file)

# A daemon without a token has nothing to prove after an update: it is
# set up where needed and started without waiting.
unbound=
if [ -n "$daemon" ] && [ ! -e "$token" ]; then
	unbound=yes
fi
if [ -n "$unbound" ] && [ ! -e "$config" ]; then
	case $anchor in
	'') die "$config does not exist; a new machine needs --anchor KEY@URL" ;;
	SHA256:*@https://*) ;;
	*) die "--anchor needs KEY@URL[,URL...], such as SHA256:...@https://192.0.2.10:7432" ;;
	esac
	if [ -z "$identity" ]; then
		identity=$(hostname -f 2>/dev/null || uname -n)
		identity=$(printf '%s\n' "$identity" | tr 'A-Z' 'a-z')
	fi
elif [ -n "$anchor$identity" ]; then
	say "$config exists and stays; --anchor and --identity are not used"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
ck=$tmp/checked
mkdir "$ck"

# fetch URL FILE
fetch() {
	if command -v curl >/dev/null; then
		curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null; then
		wget -q -O "$2" "$1"
	else
		die "neither curl nor wget to download the release; download it and pass its directory"
	fi
}

if [ -z "$dir" ]; then
	dir=$tmp/release
	mkdir "$dir"
	if [ -n "$version" ]; then
		base=$url/download/$version
	else
		base=$url/latest/download
	fi
	files="SHA256SUMS SHA256SUMS.sig"
	for b in "$@"; do
		files="$files $b-linux-$arch"
	done
	[ -z "$unbound" ] || files="$files ergosumd.service ergosumd.openrc ergosum.sysusers"
	say "downloading ${version:-the latest release} from $url"
	for f in $files; do
		fetch "$base/$f" "$dir/$f" || die "downloading $base/$f failed"
	done
fi

pin=
if [ -z "$signers" ]; then
	signers=/etc/ergosum/release-signers
	if [ ! -e "$signers" ]; then
		release_signers >"$tmp/release-signers"
		signers=$tmp/release-signers
		pin=yes
	fi
fi
[ -r "$signers" ] || die "no release keys at $signers"

# The signature covers SHA256SUMS, the checksums cover the files.
out=$(ssh-keygen -Y verify -f "$signers" -I release -n ergosum-release \
	-s "$dir/SHA256SUMS.sig" <"$dir/SHA256SUMS" 2>&1) ||
	die "signature over $dir/SHA256SUMS does not verify against ${pin:+the release keys in this script}${pin:-$signers}: $out"
say "signature over SHA256SUMS verified"
if [ -n "$pin" ]; then
	install -D -m 0644 "$signers" /etc/ergosum/release-signers
	say "release keys of this script kept in /etc/ergosum/release-signers for updates"
fi

# checked FILE: a private copy of the release file in $ck, checked against
# SHA256SUMS, so that it cannot change between the check and its use.
checked() {
	[ -f "$dir/$1" ] || die "$dir/$1 is missing"
	ck_want=$(awk -v f="$1" '$2 == f || $2 == "*" f {n++; h = $1} END {if (n == 1) print h}' "$dir/SHA256SUMS")
	[ -n "$ck_want" ] || die "$1 is not listed once in SHA256SUMS"
	cp "$dir/$1" "$ck/$1"
	ck_got=$(sha256sum "$ck/$1" | awk '{print $1}')
	[ "$ck_got" = "$ck_want" ] || die "$1 does not match SHA256SUMS"
}

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

# as_ergosum CMD [ARG...]: runs CMD as the daemon's user, which has no
# login shell.
as_ergosum() {
	if command -v runuser >/dev/null; then
		runuser -u ergosum -- "$@"
	else
		# BusyBox su takes options anywhere; after -- they are CMD's.
		# shellcheck disable=SC2016 # expanded by the inner shell
		su -s /bin/sh -c 'exec "$0" "$@"' ergosum -- "$@"
	fi
}

# ensure_users: the daemon's user ergosum, and the group ergosum-token
# whose members (Vault Agent's user) read the token.
ensure_users() {
	if command -v systemd-sysusers >/dev/null; then
		if [ ! -e /etc/sysusers.d/ergosum.conf ]; then
			checked ergosum.sysusers
			install -D -m 0644 "$ck/ergosum.sysusers" /etc/sysusers.d/ergosum.conf
		fi
		systemd-sysusers /etc/sysusers.d/ergosum.conf
		return 0
	fi
	nologin=$(command -v nologin || echo /sbin/nologin)
	if command -v useradd >/dev/null; then
		getent group ergosum-token >/dev/null || groupadd -r ergosum-token
		id ergosum >/dev/null 2>&1 ||
			useradd -r -U -M -d /var/lib/ergosum -s "$nologin" -c ergosum ergosum
		usermod -a -G ergosum-token ergosum
	elif command -v adduser >/dev/null; then # BusyBox (Alpine)
		getent group ergosum-token >/dev/null || addgroup -S ergosum-token
		getent group ergosum >/dev/null || addgroup -S ergosum
		id ergosum >/dev/null 2>&1 ||
			adduser -S -D -H -h /var/lib/ergosum -s "$nologin" -G ergosum ergosum
		id -nG ergosum | tr ' ' '\n' | grep -qx ergosum-token ||
			addgroup ergosum ergosum-token
	else
		die "no systemd-sysusers, useradd or adduser; create the user ergosum and the group ergosum-token by hand"
	fi
}

# install_service: the systemd unit or OpenRC script, unless there is one.
install_service() {
	if command -v systemctl >/dev/null; then
		for u in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
			[ ! -e "$u/ergosumd.service" ] || return 0
		done
		checked ergosumd.service
		install -m 0644 "$ck/ergosumd.service" /etc/systemd/system/ergosumd.service
		if [ -d /run/systemd/system ]; then
			systemctl daemon-reload
		fi
	elif [ -x /sbin/openrc-run ]; then
		[ ! -e /etc/init.d/ergosumd ] || return 0
		checked ergosumd.openrc
		install -m 0755 "$ck/ergosumd.openrc" /etc/init.d/ergosumd
	fi
}

# write_config: a new machine's configuration, which ergosumd checks (and
# for which it creates the key) before it takes its place.
write_config() {
	install -d -m 0755 "$(dirname "$config")"
	{
		echo "# Written by install.sh. All settings: examples/ergosumd.yaml in"
		echo "# the ergosum repository."
		echo "identity: $identity"
		echo "authorities:"
		echo "  - key: \"${anchor%%@*}\""
		echo "    urls:"
		printf '%s\n' "${anchor#*@}" | tr ',' '\n' | sed 's/^\(.*\)$/      - "\1"/'
	} >"$config.new"
	chmod 0644 "$config.new"
	if ! out=$(as_ergosum "$BINDIR/ergosumd" request -config "$config.new" 2>&1); then
		rm -f "$config.new"
		die "ergosumd refuses the configuration (identity \"$identity\"; another one with --identity): $out"
	fi
	mv -f "$config.new" "$config"
	say "$config written for $identity"
}

# start_daemon: (re)starts ergosumd and enables it at boot.
start_daemon() {
	if [ -n "${RESTART_CMD:-}" ]; then
		sh -c "$RESTART_CMD"
	elif [ -d /run/systemd/system ]; then
		systemctl enable ergosumd && systemctl restart ergosumd
	elif command -v rc-service >/dev/null; then
		rc-update add ergosumd default && rc-service ergosumd restart
	else
		say "no systemd or OpenRC; start ergosumd by hand"
		return 0
	fi
	say "ergosumd started; once its binding is recorded it writes its token to $token"
}

# setup: what a machine needs before its first token, where it is missing;
# then (re)start ergosumd and print the binding request.
setup() {
	ensure_users
	state=$(config_value state_dir)
	state=${state:-/var/lib/ergosum}
	[ -d "$state" ] || install -d -o ergosum -g ergosum -m 0700 "$state"
	install_service
	[ -e "$config" ] || write_config
	if [ -n "$restart" ]; then
		start_daemon
	else
		say "not started (--no-restart)"
	fi
	say "binding request; an administrator records it with \"ergosum bind FILE\":"
	echo
	as_ergosum "$BINDIR/ergosumd" request -config "$config"
	echo
	say "checks of kind ip need the callback port (TCP 7433) open to the authorities"
}

# fresh MARKER [VERSION]: a token newer than MARKER and, with a metrics
# file, VERSION in build_info. The way back may lead to a build from before
# that metric, so it passes no VERSION.
fresh() {
	[ -f "$token" ] && [ "$token" -nt "$1" ] || return 1
	[ -n "$metrics" ] && [ -n "$2" ] || return 0
	grep -q "^machine_identity_build_info{version=\"$2\"," "$metrics" 2>/dev/null
}

wait_fresh() {
	n=0
	while [ "$n" -lt "$wait" ]; do
		fresh "$1" "${2:-}" && return 0
		sleep 1
		n=$((n + 1))
	done
	return 1
}

installed_daemon=
for b in "$@"; do
	file=$b-linux-$arch
	checked "$file"
	chmod 0755 "$ck/$file"

	new=$(version_of "$ck/$file")
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
	cp "$ck/$file" "$BINDIR/.$b.new"
	chmod 0755 "$BINDIR/.$b.new"
	mv -f "$BINDIR/.$b.new" "$BINDIR/$b"
	say "$b ${cur:-(none)} -> $new installed${cur:+, previous binary kept as $BINDIR/$b.old}"
	case $b in
	ergosum) say "restart the authority by hand and unseal it" ;;
	ergosumd) installed_daemon=$new installed_daemon_old=$cur ;;
	esac
done

if [ -n "$unbound" ]; then
	setup
	exit 0
fi
[ -n "$installed_daemon" ] || exit 0
if [ -z "$restart" ]; then
	say "not restarted (--no-restart)"
	exit 0
fi

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
if wait_fresh "$marker"; then
	die "ergosumd $installed_daemon failed; $installed_daemon_old is back and has a new token"
fi
die "ergosumd $installed_daemon failed, and $installed_daemon_old has no new token either"
