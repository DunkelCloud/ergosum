#!/bin/sh
# Copies the installer and the service files of a release into OUTDIR, under
# the names deploy/install.sh downloads. The release workflow and
# test/install/release.sh use it, so that the two cannot drift apart.
#
#   scripts/release-files.sh OUTDIR
set -eu

out=${1:?usage: scripts/release-files.sh OUTDIR}
case $out in
/* | [A-Za-z]:[/\]*) ;; # absolute, also C:/ or C:\ in Git Bash
*) out=$PWD/$out ;;
esac
cd "$(dirname "$0")/.."
cp deploy/install.sh "$out/install.sh"
# The daemon's, for a new machine.
cp deploy/systemd/ergosumd.service "$out/ergosumd.service"
cp deploy/openrc/ergosumd "$out/ergosumd.openrc"
cp deploy/sysusers.d/ergosum.conf "$out/ergosum.sysusers"
cp deploy/launchd/io.github.dunkelcloud.ergosumd.plist "$out/ergosumd.plist"
# The authority's, for install.sh --authority.
cp deploy/systemd/ergosum.service "$out/ergosum.service"
cp deploy/openrc/ergosum "$out/ergosum.openrc"
cp deploy/sysusers.d/ergosum-authority.conf "$out/ergosum-authority.sysusers"
