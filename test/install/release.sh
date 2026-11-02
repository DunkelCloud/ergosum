#!/usr/bin/env bash
# Lays out releases as GitHub serves them, signed with a key made for the
# test, and deploy/install.sh with that key in place of the release keys it
# carries, so that the way a machine gets its first release keys is tested
# as well. test/install/run.sh and test/install/macos.sh install from them.
#
#   test/install/release.sh W OS ARCH BIN...
#
# Each BIN is a directory with a build of ergosumd with a release version
# for OS and ARCH; the last is the latest release. In W the script leaves
# www/ (the web root: download/VERSION/ and latest/download/), install.sh,
# release-signers (the test key) and other-signers (another key).
set -euo pipefail

W=$1 OS=$2 ARCH=$3
shift 3
ROOT=$(cd "$(dirname "$0")/../.." && pwd)

sums() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$@"
	else
		shasum -a 256 "$@" # macOS
	fi
}

for k in release other; do
	ssh-keygen -q -t ed25519 -N "" -C "$k" -f "$W/$k-key"
	echo "release namespaces=\"ergosum-release\" $(cat "$W/$k-key.pub")" >"$W/$k-signers"
done
rel=
for bin in "$@"; do
	version=$("$bin/ergosumd" version | awk '{print $2}')
	rel=$W/www/download/$version
	mkdir -p "$rel"
	cp "$bin/ergosumd" "$rel/ergosumd-$OS-$ARCH"
	"$ROOT/scripts/release-files.sh" "$rel"
	(cd "$rel" && sums -- * >SHA256SUMS)
	ssh-keygen -q -Y sign -f "$W/release-key" -n ergosum-release "$rel/SHA256SUMS"
done
mkdir -p "$W/www/latest"
cp -R "$rel" "$W/www/latest/download"

# The test key in place of the release keys the script carries.
awk -v keys="$W/release-signers" '
	/^release_signers\(\) \{$/ { fn = 1 }
	fn && /^EOF$/ { while ((getline l < keys) > 0) print l; skip = 0; fn = 0 }
	!skip { print }
	fn && /^\tcat <<.EOF.$/ { skip = 1 }
' "$ROOT/deploy/install.sh" >"$W/install.sh"
grep -qF "$(cat "$W/release-key.pub")" "$W/install.sh" || { echo "FAIL: test key not in the script" >&2; exit 1; }

# Readable for the web server and the machines; the private keys stay
# private.
chmod a+rX "$W"
chmod -R a+rX "$W/www"
chmod a+r "$W/install.sh" "$W/release-signers" "$W/other-signers"
