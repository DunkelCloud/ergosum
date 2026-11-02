#!/usr/bin/env bash
# The Vault side with the real binaries, a Vault dev server and Vault Agent in
# Linux network namespaces.
#
#   host1 198.51.100.20 --veth-- 198.51.100.2 authority: ergosum serve, vault server -dev
#        (segment 198.51.100.0/24)
#
# deploy/vault/machine-auth.sh sets up mount, role and policy next to existing
# configuration it must leave alone. Tokens with another audience, another
# issuer, an unknown key, or for an identity the role does not admit are
# refused, and host1 cannot read another machine's secrets. Vault Agent on
# host1 logs in with the identity token, renders the backup settings from
# examples/vault-agent, and a restic backup runs with them. After the Vault
# token's max TTL the agent logs in again with the token that is in the file
# at that time. The authority key changes (a new instance; both keys, then only
# the new one). With -all-identities the role admits every identity of the
# trust domain and none of another, and each machine still reads only its own
# secrets. The rollback removes mount and policy and nothing else.
#
# Needs root, iproute2, curl, jq, ssh-keygen, restic and vault. Usage:
#   sudo BIN=dist VAULT_BIN=/usr/local/bin/vault test/vault/run.sh
set -euo pipefail

BIN=${BIN:-$(pwd)/dist}
VAULT_BIN=${VAULT_BIN:-$(command -v vault)}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
SETUP=$SRC/deploy/vault/machine-auth.sh
W=$(mktemp -d /tmp/ergosum-vault.XXXXXX)
declare -A PID
NS=(authority host1)
H1=host1.example.com
H2=host2.example.com
ISS=https://ergosum.example.com

export VAULT=$VAULT_BIN VAULT_ADDR=http://198.51.100.2:8200 VAULT_TOKEN=root

log() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	for f in "$W"/*.log; do [ -f "$f" ] && { echo "--- $f"; tail -n 20 "$f"; }; done >&2
	exit 1
}

cleanup() {
	set +e
	for p in "${PID[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	for ns in "${NS[@]}"; do ip netns del "$ns" 2>/dev/null; done
	if [ "${KEEP:-}" = "" ]; then rm -rf "$W"; fi
}
trap cleanup EXIT

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
v() { in_ns authority "$VAULT_BIN" "$@"; }
stop() { kill "${PID[$1]}"; wait "${PID[$1]}" 2>/dev/null || true; unset "PID[$1]"; }
wait_for() { # seconds what command...
	local t=$1 what=$2
	shift 2
	for _ in $(seq $((t * 5))); do "$@" && return 0; sleep 0.2; done
	fail "timed out: $what"
}
count() { grep -c -- "$1" "$2" || true; }
pem() { sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' "$W/$1.keygen" > "$W/$1.pem"; }
fingerprint() { awk '/^fingerprint:/ {print $2}' "$W/$1.keygen"; }
kid() { awk '/^kid:/ {print $2}' "$W/$1.keygen"; }
b64url_decode() {
	local s
	s=$(tr '_-' '/+')
	case $((${#s} % 4)) in 2) s="$s==" ;; 3) s="$s=" ;; esac
	printf '%s' "$s" | base64 -d
}

log "network and Vault dev server"
for ns in "${NS[@]}"; do
	ip netns add "$ns"
	in_ns "$ns" ip link set lo up
done
ip link add seg netns authority type veth peer name eth0 netns host1
in_ns authority ip addr add 198.51.100.2/24 dev seg
in_ns authority ip link set seg up
in_ns host1 ip addr add 198.51.100.20/24 dev eth0
in_ns host1 ip link set eth0 up

in_ns authority "$VAULT_BIN" server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 > "$W/vault.log" 2>&1 &
PID[vault]=$!
vault_up() { v status >/dev/null 2>&1; }
wait_for 20 "Vault dev server" vault_up
"$VAULT_BIN" version

# Configuration that is already there and must stay as it is.
v auth enable -path=people userpass >/dev/null
v auth enable -path=occupied userpass >/dev/null
v policy write existing - <<<'path "secret/data/existing/*" { capabilities = ["read"] }' >/dev/null
v policy write taken - <<<'path "secret/data/taken/*" { capabilities = ["read"] }' >/dev/null
v kv put secret/existing/x value=1 >/dev/null
before=$(v auth list -format=json | jq -S 'with_entries(.value |= {type, accessor, description})'; v policy read existing; v policy read taken)

log "keys and bindings"
for k in a c; do
	"$BIN/ergosum" keygen -out "$W/$k.key" > "$W/$k.keygen"
	pem "$k"
done
ssh-keygen -q -t ed25519 -N "" -C alice@example.com -f "$W/alice"

daemon_config() { # dir identity port authority
	mkdir -p "$W/$1/state" "$W/$1/run"
	cat > "$W/$1/ergosumd.yaml" <<EOF
identity: $2
state_dir: $W/$1/state
token_file: $W/$1/run/token
token_group: "-"
metrics_file: ""
authorities:
  - url: https://198.51.100.2:$3
    key: "$(fingerprint "$4")"
EOF
}
event() { # identity daemon-dir [trust-domain]
	local fp td=${3:-example.com}
	fp=$(in_ns host1 "$BIN/ergosumd" fingerprint --config "$W/$2/ergosumd.yaml")
	printf 'ergosum binding v1\nkind binding.set\ntrust-domain %s\nidentity %s\nepoch 1\nkey %s\ncheck net 198.51.100.0/24\n' "$td" "$1" "$fp" > "$W/$1.$td.txt"
	ssh-keygen -q -Y sign -f "$W/alice" -n ergosum-binding "$W/$1.$td.txt"
	jq -n --arg td "$td" --arg id "$1" --arg key "$fp" --rawfile sig "$W/$1.$td.txt.sig" '{
		v: 1, kind: "binding.set", trust_domain: $td, identity: $id,
		epoch: 1, key: $key, checks: [{type: "net", target: "198.51.100.0/24"}], signatures: [$sig]
	}' > "$W/$1.$td.json"
}
daemon_config host1 "$H1" 7432 a
daemon_config host2 "$H2" 7432 a
event "$H1" host1
event "$H2" host2

ops_up() { [ "$(in_ns authority curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/healthz" || true)" = 200 ]; }
authority() { # name key port issuer audience [trust-domain]
	local td=${6:-example.com}
	mkdir -p "$W/$1"
	cat > "$W/$1/serve.yaml" <<EOF
instance: $1
trust_domain: $td
issuer: $4
audience: $5
signing_key: $W/$2.key
journal: $W/$1/journal.db
control_socket: $W/$1/control.sock
listen: ":$3"
listen_all_interfaces: true
ops_listen: "127.0.0.1:$(($3 + 2))"
callbacks:
  networks:
    - cidr: 198.51.100.0/24
      source: 198.51.100.2
registry:
  admins:
    alice: "$(cat "$W/alice.pub")"
  approvals:
    binding.set: {threshold: 1, keys: [alice]}
    binding.revoked: {threshold: 1, keys: [alice]}
EOF
	in_ns authority "$BIN/ergosum" serve --config "$W/$1/serve.yaml" --log-format text > "$W/$1.log" 2>&1 &
	PID[$1]=$!
	wait_for 10 "authority $1" ops_up $(($3 + 2))
	for id in "$H1" "$H2"; do
		[ -f "$W/$id.$td.json" ] || continue
		code=$(in_ns host1 curl -sk -o "$W/bind.out" -w '%{http_code}' -H 'Content-Type: application/json' \
			--data @"$W/$id.$td.json" "https://198.51.100.2:$3/v1/bindings")
		[ "$code" = 201 ] || { cat "$W/bind.out"; fail "binding $id at $1 returned $code"; }
	done
}
authority a a 7432 "$ISS" vault

# token_once DIR [IDENTITY PORT AUTHORITY]: run a daemon with host1's (or
# DIR's own) key until it holds a token, and keep the token in $W/DIR.jwt.
token_once() {
	if [ $# -gt 1 ]; then
		daemon_config "$1" "$2" "$3" "$4"
		cp "$W/host1/state/identity.key" "$W/$1/state/"
	fi
	rm -f "$W/$1/run/token"
	in_ns host1 "$BIN/ergosumd" run --config "$W/$1/ergosumd.yaml" --log-format text > "$W/daemon-$1.log" 2>&1 &
	local p=$!
	for _ in $(seq 50); do [ -s "$W/$1/run/token" ] && break; sleep 0.2; done
	kill "$p"
	wait "$p" 2>/dev/null || true
	[ -s "$W/$1/run/token" ] || fail "no token for $1"
	cp "$W/$1/run/token" "$W/$1.jwt"
}

log "machine-auth.sh refuses what it does not own"
rollback() { in_ns authority "$SETUP" rollback "$@"; }
setup() { in_ns authority "$SETUP" "$@" -issuer "$ISS" -trust-domain example.com; }
setup apply -yes -path occupied -key "$W/a.pem" -identity "$H1" 2> "$W/refuse.err" && fail "took over auth/occupied"
grep -q 'not created by this script' "$W/refuse.err" || { cat "$W/refuse.err"; fail "auth/occupied: wrong refusal"; }
setup apply -yes -policy taken -key "$W/a.pem" -identity "$H1" 2> "$W/refuse.err" && fail "took over policy taken"
grep -q 'not written by this script' "$W/refuse.err" || { cat "$W/refuse.err"; fail "policy taken: wrong refusal"; }
setup apply -yes -key "$W/a.pem" 2> /dev/null && fail "applied without admitted identities"
setup apply -yes -key "$W/a.key" -identity "$H1" 2> /dev/null && fail "accepted a private key"
v auth list -format=json | jq -e 'has("machine/") | not' >/dev/null || fail "a refused run left a mount"

log "plan and apply"
setup plan -key "$W/a.pem" -identity "$H1" -ttl 20s | tee "$W/plan.out"
grep -q '^+ auth/machine: enable jwt' "$W/plan.out" || fail "plan does not create the mount"
v auth list -format=json | jq -e 'has("machine/") | not' >/dev/null || fail "plan changed Vault"
setup apply -yes -key "$W/a.pem" -identity "$H1" -ttl 20s
setup plan -key "$W/a.pem" -identity "$H1" -ttl 20s | tee "$W/plan.out"
grep -q '^No changes.' "$W/plan.out" || fail "second plan is not empty"
v read -format=json auth/machine/role/host | jq -e --arg s "spiffe://example.com/host/$H1" '.data |
	.bound_audiences == ["vault"] and .user_claim == "sub" and .bound_claims.sub == [$s] and
	.claim_mappings == {host: "host"} and .token_ttl == 20 and .token_max_ttl == 20 and
	.token_policies == ["host-secrets"]' >/dev/null || fail "unexpected role"
after=$(v auth list -format=json | jq -S 'with_entries(select(.key != "machine/") | .value |= {type, accessor, description})'; v policy read existing; v policy read taken)
[ "$before" = "$after" ] || fail "existing configuration changed"

log "backup settings in Vault, restic repository"
v kv put "secret/host/$H1/backup/config" repository="$W/repo" >/dev/null
# A quote and a space in the password exercise the template's shell quoting.
v kv put "secret/host/$H1/backup/credentials" restic_password="it's secret" \
	access_key_id=AKIDEXAMPLE secret_access_key=example-secret-key >/dev/null
v kv put "secret/host/$H2/backup/credentials" restic_password=other \
	access_key_id=AKIDOTHER secret_access_key=other-secret-key >/dev/null
RESTIC_REPOSITORY=$W/repo RESTIC_PASSWORD="it's secret" restic init -q

log "tokens Vault must refuse"
login() { # token-file; prints the Vault token
	in_ns host1 env -u VAULT_TOKEN "$VAULT_BIN" write -field=token auth/machine/login role=host jwt="$(cat "$1")" 2> "$W/login.err"
}
refused() { # token-file reason what
	if login "$1" >/dev/null; then fail "$3 was accepted"; fi
	grep -qiE "$2" "$W/login.err" || { cat "$W/login.err"; fail "$3 refused for another reason"; }
	echo "refused: $3"
}
authority aud a 7442 "$ISS" other
token_once via-aud "$H1" 7442 a
stop aud
refused "$W/via-aud.jwt" 'aud' "audience other than vault"
authority iss a 7452 https://other.example.com vault
token_once via-iss "$H1" 7452 a
stop iss
refused "$W/via-iss.jwt" 'iss' "foreign issuer"
authority foreign c 7462 "$ISS" vault
token_once via-foreign "$H1" 7462 c
stop foreign
refused "$W/via-foreign.jwt" 'signature|verif' "key unknown to Vault"
token_once host2
refused "$W/host2.jwt" 'bound claim|claim' "identity the role does not admit"

log "host1 reads its own secrets only"
token_once via-a "$H1" 7432 a
T1=$(login "$W/via-a.jwt") || { cat "$W/login.err"; fail "host1 refused"; }
as_host1() { in_ns host1 env VAULT_TOKEN="$T1" "$VAULT_BIN" "$@"; }
as_host1 token lookup -format=json | jq -e --arg h "$H1" '.data.meta.host == $h' >/dev/null || fail "no host in token metadata"
as_host1 kv get -field=repository "secret/host/$H1/backup/config" >/dev/null || fail "host1 cannot read its config"
as_host1 kv get "secret/host/$H2/backup/credentials" >/dev/null 2>&1 && fail "host1 read host2's credentials"
as_host1 kv get secret/existing/x >/dev/null 2>&1 && fail "host1 read secret/existing"
echo "isolation ok"

log "Vault Agent renders the backup settings; a backup runs with them"
in_ns host1 "$BIN/ergosumd" run --config "$W/host1/ergosumd.yaml" --log-format text > "$W/host1.log" 2>&1 &
PID[host1]=$!
sed -e "s#https://vault.example.com:8200#$VAULT_ADDR#" \
	-e "s#/run/ergosum/token#$W/host1/run/token#" \
	-e "s#/etc/vault-agent/backup.env.ctmpl#$SRC/examples/vault-agent/backup.env.ctmpl#" \
	-e "s#/run/vault-agent/backup.env#$W/host1/run/backup.env#" \
	"$SRC/examples/vault-agent/agent.hcl" > "$W/agent.hcl"
[ "$(grep -c "$W\|$SRC\|$VAULT_ADDR" "$W/agent.hcl")" = 4 ] || fail "agent.hcl: substitution failed"
in_ns host1 env -u VAULT_TOKEN -u VAULT_ADDR "$VAULT_BIN" agent -config="$W/agent.hcl" > "$W/agent.log" 2>&1 &
PID[agent]=$!
wait_for 30 "rendered backup settings" test -s "$W/host1/run/backup.env"
[ "$(stat -c %a "$W/host1/run/backup.env")" = 600 ] || fail "backup.env is not 0600"
in_ns host1 bash -c ". '$W/host1/run/backup.env' && restic backup -q '$SRC/docs' && restic snapshots --json" > "$W/snapshots.json"
jq -e --arg p "$SRC/docs" 'length == 1 and .[0].paths == [$p]' "$W/snapshots.json" >/dev/null || fail "no snapshot"
in_ns host1 bash -c ". '$W/host1/run/backup.env' && [ \"\$AWS_ACCESS_KEY_ID\" = AKIDEXAMPLE ]" || fail "wrong credentials rendered"
echo "backup ok"

log "the agent logs in again after the token's max TTL, with the token in the file"
logins() { count 'authentication successful' "$W/agent.log"; }
failures() { count 'error authenticating' "$W/agent.log"; }
more_logins() { [ "$(logins)" -gt "$1" ]; }
more_failures() { [ "$(failures)" -gt "$1" ]; }
wait_for 60 "second login" more_logins 1
stop host1
cp "$W/via-foreign.jwt" "$W/host1/run/token.tmp" && mv "$W/host1/run/token.tmp" "$W/host1/run/token"
wait_for 60 "login with the foreign token to fail" more_failures 0
n=$(logins)
rm -f "$W/host1/run/token"
in_ns host1 "$BIN/ergosumd" run --config "$W/host1/ergosumd.yaml" --log-format text >> "$W/host1.log" 2>&1 &
PID[host1]=$!
wait_for 60 "login with the renewed token" more_logins "$n"
echo "logins: $(logins), failed: $(failures)"

log "key change: a new instance a2, both keys, then only the new one"
"$BIN/ergosum" keygen -out "$W/a2.key" > "$W/a2.keygen"
pem a2
setup apply -yes -key "$W/a.pem" -key "$W/a2.pem" -identity "$H1" -ttl 20s
authority a2 a2 7472 "$ISS" vault
stop host1
daemon_config host1 "$H1" 7472 a2
rm -f "$W/host1/run/token"
in_ns host1 "$BIN/ergosumd" run --config "$W/host1/ergosumd.yaml" --log-format text >> "$W/host1.log" 2>&1 &
PID[host1]=$!
wait_for 10 "token from a2" test -s "$W/host1/run/token"
[ "$(cut -d. -f1 "$W/host1/run/token" | b64url_decode | jq -r .kid)" = "$(kid a2)" ] || fail "token not from a2"
n=$(logins)
wait_for 60 "login with the token from a2" more_logins "$n"
setup apply -yes -key "$W/a2.pem" -identity "$H1" -ttl 20s
stop a
refused "$W/via-a.jwt" 'signature|verif' "token of the removed key"
cp "$W/host1/run/token" "$W/a2.jwt"
T2=$(login "$W/a2.jwt") || { cat "$W/login.err"; fail "token from a2 refused"; }
echo "key change ok"

log "every identity of the trust domain, none of another"
setup plan -key "$W/a2.pem" -all-identities -ttl 20s | tee "$W/plan.out"
grep -q '^~ auth/machine/role/host: update' "$W/plan.out" || fail "plan does not update the role"
grep -q '^= auth/machine/config: unchanged' "$W/plan.out" || fail "plan changes the keys"
grep -q '^= policy host-secrets: unchanged' "$W/plan.out" || fail "plan changes the policy"
setup apply -yes -key "$W/a2.pem" -identity "$H1" -all-identities 2> /dev/null && fail "accepted -identity with -all-identities"
setup apply -yes -key "$W/a2.pem" -all-identities -ttl 20s
setup plan -key "$W/a2.pem" -all-identities -ttl 20s | tee "$W/plan.out"
grep -q '^No changes.' "$W/plan.out" || fail "second plan with -all-identities is not empty"
v read -format=json auth/machine/role/host | jq -e '.data | .bound_claims_type == "glob" and
	.bound_claims == {sub: "spiffe://example.com/host/*"}' >/dev/null || fail "unexpected role"
n=$(logins)
wait_for 60 "login of host1's agent" more_logins "$n"
stop host1
daemon_config host2 "$H2" 7472 a2
token_once host2
T3=$(login "$W/host2.jwt") || { cat "$W/login.err"; fail "host2 refused"; }
as_host2() { in_ns host1 env VAULT_TOKEN="$T3" "$VAULT_BIN" "$@"; }
as_host2 kv get -field=restic_password "secret/host/$H2/backup/credentials" >/dev/null || fail "host2 cannot read its credentials"
as_host2 kv get "secret/host/$H1/backup/config" >/dev/null 2>&1 && fail "host2 read host1's config"
event "$H1" host1 other.example
authority other a2 7482 "$ISS" vault other.example
token_once via-other "$H1" 7482 a2
stop other
refused "$W/via-other.jwt" 'bound claim|claim' "identity of another trust domain"
echo "all identities ok"

log "rollback"
rollback -yes
v auth list -format=json | jq -e 'has("machine/") | not' >/dev/null || fail "mount still there"
v policy list -format=json | jq -e 'index("host-secrets") == null' >/dev/null || fail "policy still there"
after=$(v auth list -format=json | jq -S 'with_entries(.value |= {type, accessor, description})'; v policy read existing; v policy read taken)
[ "$before" = "$after" ] || fail "rollback changed existing configuration"
for t in "$T1" "$T2" "$T3"; do
	in_ns host1 env VAULT_TOKEN="$t" "$VAULT_BIN" token lookup >/dev/null 2>&1 && fail "a token of the mount survived"
done
rollback -yes | grep -q 'nothing to roll back' || fail "second rollback"

log "OK"
