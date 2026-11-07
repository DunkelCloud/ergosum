# Sourced in the containers of test/install/run.sh by machine.sh and
# authority.sh: the packages that install.sh needs, so that each
# distribution brings the tools it is tested with. Debian: useradd and wget;
# Ubuntu 20.04: systemd (systemctl, systemd-sysusers) without
# /etc/sysusers.d, and curl; Alpine: BusyBox and OpenRC.
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
