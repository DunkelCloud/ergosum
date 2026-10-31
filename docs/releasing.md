# Releases

A release is a GitHub release of a tag `vMAJOR.MINOR.PATCH`: the
binaries, the image as an archive, `SHA256SUMS` over all of them, and
`SHA256SUMS.sig`, an SSH signature over `SHA256SUMS` in the namespace
`ergosum-release`. The keys that may sign are in
[`release-signers`](../release-signers); today one key,
`SHA256:xcJy5kiogfRmaX7n8ednlEIcxJUxQGiN1QJgXxhKeSc`.

CI builds a release but cannot sign one: the key stays with its holder,
who signs on their own machine. The builds are reproducible
(`scripts/build.sh`), so anyone can rebuild a release and compare.

| File | Contents |
| --- | --- |
| `ergosumd-linux-{amd64,arm64}` | the daemon |
| `ergosum-linux-{amd64,arm64}` | the authority and the administrator tool |
| `ergosum-{windows,darwin}-{amd64,arm64}[.exe]` | the administrator tool |
| `ergosum-image-linux-{amd64,arm64}.tar` | the OCI image, for `docker load` |
| `SHA256SUMS`, `SHA256SUMS.sig` | checksums and their signature |

## Verifying a release

With `release-signers` from the repository, in the directory with the
downloaded files:

```sh
ssh-keygen -Y verify -f release-signers -I release -n ergosum-release \
  -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

`ssh-keygen` needs OpenSSH 8.1 or later. With an `ergosum` binary at hand,
on any system:

```sh
ergosum release verify -signers release-signers DIR
```

It checks the signature and every listed file present in `DIR`, and names
the ones that are not there.

To rebuild a binary, check out the tag and build with the version and the
full commit hash from the release notes; the result must match
`SHA256SUMS`:

```sh
git checkout vX.Y.Z
GOOS=linux GOARCH=amd64 VERSION=vX.Y.Z COMMIT=$(git rev-parse HEAD) \
  scripts/build.sh /tmp/rebuild ergosumd
sha256sum /tmp/rebuild/ergosumd
```

## Installing and updating

Once per machine, as root, install the release keys:

```sh
install -m 0644 release-signers /etc/ergosum/release-signers
```

Then copy the release files and [`deploy/install.sh`](../deploy/install.sh)
to the machine and run it as root:

```sh
deploy/install.sh /tmp/ergosum-vX.Y.Z           # the daemon
deploy/install.sh /tmp/ergosum-vX.Y.Z ergosum   # an authority
```

The script checks the signature against `/etc/ergosum/release-signers` and
the checksum of every file it installs, refuses an older version unless
given `--allow-downgrade`, and keeps the installed binary as
`/usr/bin/NAME.old`. It restarts `ergosumd` (systemd or OpenRC) and waits
for a new token; without one it puts the old binary back and restarts it.
It changes neither configuration nor state. Users, units and configuration
of a new machine are set up as in [operations](operations.md).

An authority is not restarted, since it comes back sealed: restart it,
unseal it, and check `/healthz`. The way back is
`mv /usr/bin/ergosum.old /usr/bin/ergosum` and another restart. Update
authorities one at a time.

For an authority in a container, verify the release as above, then:

```sh
docker load -i ergosum-image-linux-amd64.tar   # loads ergosum:vX.Y.Z
```

name `ergosum:vX.Y.Z` in the Compose file, recreate the container and
unseal it.

Roll out to one machine first, then to a few, then to the rest.
`machine_identity_build_info{version,commit}` shows which build runs where.

## Making a release

For the holder of a release key.

1. Tag a commit on `main` and push the tag:

   ```sh
   git tag -a vX.Y.Z -m vX.Y.Z COMMIT
   git push origin vX.Y.Z
   ```

   A pre-release (`vX.Y.Z-rc.N`) may point to a branch under test.
2. The release workflow checks the tag, runs govulncheck, builds everything
   with `scripts/build.sh`, checks that the images carry the released
   binaries, and creates a draft release with `SHA256SUMS`. Its notes name
   the commit.
3. Download `SHA256SUMS` from the draft, check that the commit in the notes
   is the one you tagged, and sign:

   ```sh
   ergosum release sign SHA256SUMS
   ```

   It shows the files, asks, signs with the release key and writes
   `SHA256SUMS.sig`, but only once the signature verifies against
   `release-signers`. The key comes from `release_key` in the
   administrator configuration (default `~/.ssh/ergosum-release.pub`): if
   the SSH agent holds it, the agent signs; otherwise `ergosum` reads the
   private key file next to the `.pub` and asks for its passphrase. It
   reads that file itself, so neither the `ssh-keygen` in `PATH` nor
   Windows line ends in the file matter. A release key is better not kept
   in the agent: the Windows agent service keeps keys across restarts, for
   every process of the user. Set `release_signers` to the repository's
   file, or give `-signers`:

   ```yaml
   release_key: ~/.ssh/ergosum-release.pub
   release_signers: ~/src/ergosum/release-signers
   ```

   With `ssh-keygen` instead: `ssh-keygen -Y sign -f ~/.ssh/ergosum-release
   -n ergosum-release SHA256SUMS`. It refuses a key file with Windows line
   ends, saying "Couldn't load public key" or "No private key found".

4. Attach `SHA256SUMS.sig` to the draft and publish it.
5. Verify the published release as above.

Only maintainers may create, move or delete `v*` tags (a repository
ruleset).

## Changing the release key

Add the new key as another line to `release-signers`, install the file on
the machines, and only then sign with the new key. Remove the old line
once no machine needs it. A key on a security key (`sk-ssh-ed25519`)
works the same way; nothing else changes.
