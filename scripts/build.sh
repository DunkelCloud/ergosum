#!/bin/sh
# Builds the binaries reproducibly: the same commit, version and target give
# the same bytes on every machine, also when cross-compiling from Windows or
# macOS. CI, the image and releases build with this script, so anyone can
# rebuild a release and compare it with the published checksums.
#
#   scripts/build.sh OUTDIR [COMMAND...]
#
# GOOS and GOARCH select the target (default: this machine). VERSION and
# COMMIT are stamped into the binaries (default: dev, unknown). COMMANDs are
# directories below cmd/ (default: ergosum ergosumd).
set -eu

out=${1:?usage: scripts/build.sh OUTDIR [COMMAND...]}
shift
[ $# -gt 0 ] || set -- ergosum ergosumd
case $out in
/* | [A-Za-z]:[/\\]*) ;; # absolute, also C:/ or C:\ in Git Bash
*) out=$PWD/$out ;;
esac
cd "$(dirname "$0")/.."

# The toolchain named in go.mod, also where a newer Go is installed; Go
# fetches it if needed and checks it against the checksum database.
GOTOOLCHAIN=$(sed -n 's/^toolchain //p' go.mod)
# Nothing from the caller's Go settings may change the bytes.
unset GOFLAGS GOEXPERIMENT GOAMD64 GOARM64 GOARM GO386
GOENV=off
CGO_ENABLED=0
export GOTOOLCHAIN GOENV CGO_ENABLED

pkg=github.com/DunkelCloud/ergosum/internal/version
ldflags="-s -w -buildid= -X $pkg.Version=${VERSION:-dev} -X $pkg.Commit=${COMMIT:-unknown}"
ext=
[ "$(go env GOOS)" = windows ] && ext=.exe

mkdir -p "$out"
for c in "$@"; do
	go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$out/$c$ext" "./cmd/$c"
done
