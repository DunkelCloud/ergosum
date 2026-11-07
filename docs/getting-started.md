# Getting started

This guide sets up a small but complete ergosum installation, step by
step:

- one **authority** on a Linux host,
- one **administrator** workstation (Linux, macOS or Windows),
- one **machine** that receives an identity token.

If a term is new to you, [How ergosum works](concepts.md) explains
it. Every step links to the page with the
details; you do not need them for a first installation.

## Before you start

**Hosts.**

- A Linux host for the authority (x86-64 or ARM64) with systemd or OpenRC,
  or with Docker, and `ssh-keygen` from OpenSSH 8.1 or later, which the
  installer uses to check the release signature. A small VM is enough. It is the most sensitive part of
  the installation: whoever controls it can issue tokens. Do not use a
  host that many people can log in to.
- A Linux server or a Mac to enroll as the first machine. It needs `curl`
  or `wget` and `ssh-keygen` from OpenSSH 8.1 or later (on Alpine: `apk
  add openssh-keygen`).
- Your workstation, with an SSH key (or a security key such as a YubiKey).

**Network.** Decide how the authority reaches the machine. Pick one:

- **Tailscale.** The authority and the machine are in the same tailnet,
  and the authority can resolve tailnet names (MagicDNS). This is the
  easiest way.
- **Fixed address.** The machine has a fixed IP address that the authority
  can reach directly, public or in your LAN. For a private LAN address, the
  authority needs an address in that LAN as well (see [Private
  networks](authority.md#private-networks)).

Then make sure that:

- the machine and your workstation reach the authority on **TCP 7432**,
- the authority reaches the machine on **TCP 7433**,
- all hosts have a correct clock (NTP). Tokens are short-lived, so a clock
  that is off by minutes breaks them.

**Names.** Choose two names:

- the **trust domain**, the name of your ergosum installation, usually your
  main domain, such as `example.com`;
- the **domain** of your machines' identities, such as `example.com` or
  `servers.example.com`. A machine `host1` becomes `host1.example.com`.
  These names do not have to exist in DNS.

## Step 1: Have an administrator key ready

Bindings are approved with SSH signatures. You can use the SSH key you
already have, or create one for ergosum on your workstation:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/ergosum-admin -C alice@example.com
```

Keep the content of the public key (`~/.ssh/ergosum-admin.pub`, one line
starting with `ssh-ed25519`) at hand: the authority needs it in step 2.

A key on a security key (`ssh-keygen -t ed25519-sk`) is better still: it
asks for a touch for every approval. See [Administrator keys and the
registry](administration.md#administrator-keys-and-the-registry).

## Step 2: Set up the authority

Run these commands as root on the authority host. On a host with Docker
you can [run the authority as a container](authority.md#running-in-a-container)
instead; the configuration is the same.

### 2.1 Install the binary

`install.sh` downloads nothing for an authority by itself, so download the
release files first, then let the script check their signature and install
`ergosum`:

```sh
mkdir -p /root/ergosum-release && cd /root/ergosum-release
base=https://github.com/DunkelCloud/ergosum/releases/latest/download
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
for f in install.sh SHA256SUMS SHA256SUMS.sig ergosum-linux-$arch; do
  curl -fsSLO "$base/$f"
done
sh install.sh "$PWD" ergosum
```

The script checks the release signature and the checksum, and installs
`/usr/bin/ergosum`. Check it with `ergosum version`.

### 2.2 Create the service user

The authority runs as a user of its own, `ergosum-authority`:

```sh
useradd --system --user-group --no-create-home \
  --home-dir /var/lib/ergosum-authority --shell /usr/sbin/nologin ergosum-authority
```

On Alpine: `addgroup -S ergosum-authority && adduser -S -D -H -h
/var/lib/ergosum-authority -s /sbin/nologin -G ergosum-authority
ergosum-authority`.

### 2.3 Create the signing key

```sh
install -d -m 0755 /etc/ergosum
ergosum keygen -out /etc/ergosum/signing.key -encrypt
chgrp ergosum-authority /etc/ergosum/signing.key
chmod 0640 /etc/ergosum/signing.key
```

`-encrypt` asks for a passphrase. The key is then stored encrypted, and
after every start the authority waits until you enter the passphrase with
`ergosum unseal`. That protects the key if the host's disk or a backup of
it is copied, at the price of a manual step after each restart. For a
first test you can leave `-encrypt` out and [encrypt the key
later](authority.md#encrypting-an-existing-key).

`keygen` prints three things. **Copy all of them into your notes**:

```text
kid:         H_VvZMhleOk8KohbcQp6ROzxTplNMSCKLFN9SwSvD7g
fingerprint: SHA256:Elq+oe+ce3oYlfjEk7G4WTk4ymiWjlWJJRA5k8TYYsQ

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUHOlYvddh+hZFsl8bQqkg5q09BM7
K5BsfKmA6jKC6cIwVZvsAjI0Ed/uhnarysq70BLz49WMsRRKyVJcfqqDFg==
-----END PUBLIC KEY-----
```

- the **fingerprint** is what machines and administrators use to recognize
  this authority (steps 3 and 4);
- the **public key** is what Vault needs to accept the tokens (step 6).

You can get both again later: the authority logs the fingerprint at every
start, and serves the public key at `http://127.0.0.1:7434/v1/keys.pem`.

### 2.4 Write the configuration

Create `/etc/ergosum/serve.yaml`. This is the smallest useful
configuration; replace the values marked below:

```yaml
# A name for this instance: lower-case letters, digits, "-" and ".".
instance: authority-a

# The name of your ergosum installation (see "Before you start").
trust_domain: example.com

# Written into every token; Vault checks it. Any URL that names your
# installation; nothing connects to it.
issuer: https://ergosum.example.com

signing_key: /etc/ergosum/signing.key

# The address and port the authority listens on: one of this host's own
# addresses, normally its tailnet address.
listen: "100.64.0.10:7432"

# Who may approve bindings: your administrator key from step 1.
registry:
  admins:
    alice: "ssh-ed25519 AAAAC3Nza... alice@example.com"
  approvals:
    binding.set:     { threshold: 1, keys: [alice] }
    binding.revoked: { threshold: 1, keys: [alice] }
```

`listen` must name an address; `0.0.0.0:7432` is refused unless you add
`listen_all_interfaces: true`, so that the authority is not exposed to the
internet by accident.

If your machine sits in a **private LAN** (step 4 with a `192.168.x.x` or
`10.x.x.x` address), add the network, so that the authority may call
machines there:

```yaml
callbacks:
  networks:
    - cidr: 192.168.10.0/24     # the machines' network
      source: 192.168.10.5      # this authority's own address in it
```

With two or more administrators, list all of them under `admins` and set
`threshold: 2` for `binding.set`: then no single administrator can bind a
machine alone. All settings are explained in [Running an
authority](authority.md#configuration) and in
[`examples/serve.yaml`](../examples/serve.yaml).

### 2.5 Start the service

With systemd, take the unit file from the repository, in the version you
installed:

```sh
v=$(ergosum version | awk 'NR == 1 {print $2}')
curl -fsSL -o /etc/systemd/system/ergosum.service \
  "https://raw.githubusercontent.com/DunkelCloud/ergosum/$v/deploy/systemd/ergosum.service"
systemctl daemon-reload
systemctl enable --now ergosum
```

With OpenRC (Alpine), take `deploy/openrc/ergosum` instead, save it as
`/etc/init.d/ergosum` with mode 0755, and run `rc-update add ergosum
default && rc-service ergosum start`.

If you created the key with `-encrypt`, unseal the authority now. It asks
for the passphrase:

```sh
ergosum unseal
```

Check that it works:

```sh
curl -s http://127.0.0.1:7434/healthz
```

It answers `ok`. `sealed` means it still waits for `ergosum unseal`. If
the service does not start, `journalctl -u ergosum` shows why; the most
common causes are a typo in `serve.yaml` and a key file with the wrong
owner or mode.

### 2.6 Open the firewall

Allow TCP 7432 to the authority from your machines and from the
administrators' workstations. Keep port 7434 closed to the outside; it
listens on `127.0.0.1` anyway.

## Step 3: Set up the admin tool on your workstation

1. Download the `ergosum` binary for your workstation from the [releases
   page](https://github.com/DunkelCloud/ergosum/releases/latest):
   `ergosum-windows-amd64.exe`, `ergosum-darwin-arm64` (Apple Silicon),
   `ergosum-darwin-amd64` (Intel Mac) or `ergosum-linux-amd64`. Rename it
   to `ergosum` (`ergosum.exe` on Windows), make it executable on Linux and
   macOS (`chmod +x ergosum`), and put it in a directory in your `PATH`.
   [Verifying a release](releasing.md#verifying-a-release) shows how to
   check its signature first.
2. Run `ergosum help`. The line "Bindings, from an administrator's
   machine" names the configuration file it reads, for example
   `~/.config/ergosum/admin.yaml` on Linux or
   `C:\Users\alice\AppData\Roaming\ergosum\admin.yaml` on Windows.
3. Create that file:

   ```yaml
   trust_domain: example.com               # as in serve.yaml
   sign_key: ~/.ssh/ergosum-admin.pub      # your public key from step 1
   authorities:
     - url: https://100.64.0.10:7432       # the authority's address and port
       key: SHA256:Elq+oe+ce3oYlfjEk7G4WTk4ymiWjlWJJRA5k8TYYsQ   # fingerprint from step 2.3
   ```

4. Test the connection:

   ```sh
   ergosum list
   ```

   It notes that only one authority is configured, lists the bindings
   (none yet) and ends with a summary such as `0 identities at
   https://100.64.0.10:7432, trust domain example.com. binding.revoked
   needs 1 of alice. binding.set needs 1 of alice.` An error that the
   authority presents another key means that the fingerprint in
   `admin.yaml` is wrong.

The tool signs through your SSH agent, or asks for the key's passphrase.
More in [Administration](administration.md#setting-up-the-admin-tool).

## Step 4: Enroll the machine

On the machine, as root (on a Mac with `sudo`), download the installer
and run it with two values:

```sh
curl -fsSLO https://github.com/DunkelCloud/ergosum/releases/latest/download/install.sh
sh install.sh --domain example.com --anchor 'SHA256:Elq+oe+ce3oYlfjEk7G4WTk4ymiWjlWJJRA5k8TYYsQ@https://100.64.0.10:7432'
```

| Option | What it is | Where you get it |
| --- | --- | --- |
| `--domain example.com` | the domain of the machine's identity; the machine becomes `<its host name>.example.com` | your choice from "Before you start"; use the same for all machines |
| `--anchor FINGERPRINT@URL` | the authority the machine talks to first, and the key it must present | the fingerprint from step 2.3, an `@`, and `https://` with an authority address *this machine* can reach and the port from `listen` |

The quotes keep the shell away from the special characters. (An authority
that answers on several addresses can be given with several URLs,
separated by commas; see [Machines](machines.md#the-two-values-you-need).)

The script:

1. downloads `ergosumd` and checks its signature,
2. creates the user `ergosum`, the group `ergosum-token`, the state
   directory and the service (systemd, OpenRC or launchd),
3. creates the machine's key, checks that the authority presents the
   expected key and writes `/etc/ergosum/ergosumd.yaml`; if the authority
   shows another key, the script stops before writing the configuration,
4. starts the daemon and prints the **binding request**.

The binding request looks like this:

```text
# Binding request for host1.example.com, written by ergosumd request at 2026-11-07T10:00:00Z.
# Keep the checks that hold for this machine and delete the others, then
# hand the file to an ergosum administrator, who runs "ergosum bind FILE".
identity host1.example.com
key SHA256:pUlP2fNzgbWeyB0Rkp4FgEBcE2Mq4mYOlUz8Qy2Wq1A
# tailnet name (tailscale status)
check tailnet host1.tailnet.example.com
# Fixed addresses have no lifetime in the kernel. An older dhclient sets DHCP leases without one too: check that each is really fixed.
# eth0: fixed public address
check ip 192.0.2.20
```

Copy it, from the first `#` line to the last line, into a file on your
workstation, such as `host1.txt`. You can print it again at any time with
`sudo -u ergosum ergosumd request`.

Finally, **allow TCP 7433 on the machine from the authority's address**.
The authority calls the machine back on this port; without it every
request fails.

[Machines](machines.md) explains all options of `install.sh`, the Mac,
updates and troubleshooting.

## Step 5: Approve the binding

On your workstation, in the directory with the file:

```sh
ergosum bind host1.txt
```

The tool shows what it is going to sign, for example the new machine, its
key and its checks. Check that the checks are the places where this
machine really is (see [Choosing
checks](administration.md#choosing-checks)); lines starting with `#` are
ignored. If something is wrong, edit the file and run the command again.
When you confirm, it signs with your key and records the binding at the
authority.

With `threshold: 2`, the tool stops after your signature and says that one
more is needed. Give the same file to the second administrator, who runs
the same command.

## Step 6: Check the result

The daemon retries every few minutes, so the token appears within about
five minutes. To skip the wait, restart the daemon. Then look for the
token and the log line `token issued`:

```sh
# Linux with systemd
systemctl restart ergosumd
ls -l /run/ergosum/token
journalctl -u ergosumd -n 20

# Mac
sudo launchctl kickstart -k system/io.github.dunkelcloud.ergosumd
ls -l /var/db/ergosum/token
tail -n 20 /var/log/ergosum/ergosumd.log
```

On Alpine (OpenRC) restart with `rc-service ergosumd restart`; the log
goes to syslog.

If no token appears, see [Troubleshooting](machines.md#troubleshooting).
The authority's log (`journalctl -u ergosum`) has audit lines for the
machine's requests, with the result of each check.

## Step 7: Use the token

The token alone does nothing yet. Use it in one of two ways:

- **With HashiCorp Vault or OpenBao.** Vault accepts the token as a login,
  and Vault Agent on the machine fetches the machine's secrets.
  [Vault](vault.md) shows the setup; it needs the public key from step 2.3.
- **Without Vault.** `ergosumd secret` seals a secret, such as a backup
  password, so that it opens only on this machine at its place. This needs
  at least two authority instances to be worthwhile; see [Secrets without
  Vault](secrets.md).

## Next steps

- **More machines:** run the same `install.sh` line on each, and approve
  each request.
- **A second authority instance**, so that tokens keep coming while one is
  down: [Several authority instances](multiple-authorities.md).
- **Monitoring:** [health check, metrics and alerts](monitoring.md).
- **Backups of machines:** decide whether the machine's key goes into
  backups; see [Backups](machines.md#backups).
