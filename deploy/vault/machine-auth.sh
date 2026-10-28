#!/usr/bin/env bash
# Sets up Vault (or OpenBao) to accept ergosum identity tokens and to hand
# every machine the backup secrets below its own name, and takes it out again.
#
# The script owns three objects and touches nothing else: a JWT auth mount,
# one role on it and one policy. An object of the same name that it did not
# create stops the run. "apply" only creates or updates these objects;
# "rollback" disables the mount, which revokes every token it issued, and
# deletes the policy.
#
#   machine-auth.sh plan     OPTIONS   show what apply would change
#   machine-auth.sh apply    OPTIONS   create or update mount, role and policy
#   machine-auth.sh rollback [-path PATH] [-policy NAME] [-yes]
#
# Options of plan and apply:
#   -issuer URL          "issuer" of the authority instances             (required)
#   -trust-domain NAME   SPIFFE trust domain of the tokens                (required)
#   -key FILE            PEM public key of an authority instance, printed by
#                        "ergosum keygen" or served at /v1/keys.pem; once per
#                        instance, the old and the new one during a key change
#                        (required)
#   -identity FQDN       admit this identity; once per machine
#   -all-identities      admit every identity of the trust domain
#                        (exactly one of -identity and -all-identities)
#   -path PATH           auth mount                     (default: machine)
#   -role NAME           role                           (default: host)
#   -policy NAME         policy                         (default: machine-backup)
#   -audience AUD        token audience                 (default: vault)
#   -ttl DURATION        Vault token TTL and max TTL    (default: 1h)
#   -kv MOUNT            KV version 2 mount             (default: secret)
#   -prefix PATH         path below the KV mount        (default: backup)
#   -yes                 do not ask before changing anything
#
# A machine reads <kv>/<prefix>/<identity>/* and nothing else; keep the
# credentials of other roles (restore, maintenance) outside that path.
#
# Needs the vault CLI with VAULT_ADDR and VAULT_TOKEN (VAULT=bao for OpenBao),
# jq and diff.
set -euo pipefail
shopt -s inherit_errexit

VAULT=${VAULT:-vault}
MARK="ergosum machine identity (managed by machine-auth.sh)"
POLICY_MARK="# Managed by ergosum machine-auth.sh; changes here are overwritten."

die() { printf 'machine-auth: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "$0"; exit 2; }

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in plan | apply | rollback) ;; -h | -help | --help) usage ;; *) die "unknown command $cmd" ;; esac

path=machine role=host policy=machine-backup audience=vault ttl=1h kv=secret prefix=backup
issuer="" domain="" all="" yes=""
keyfiles=() identities=()
while [ $# -gt 0 ]; do
	case $1 in
	-yes) yes=1 ;;
	-all-identities) all=1 ;;
	-h | -help | --help) usage ;;
	-issuer | -trust-domain | -key | -identity | -path | -role | -policy | -audience | -ttl | -kv | -prefix)
		[ $# -ge 2 ] || die "$1 needs a value"
		case $1 in
		-issuer) issuer=$2 ;;
		-trust-domain) domain=$2 ;;
		-key) keyfiles+=("$2") ;;
		-identity) identities+=("$2") ;;
		-path) path=$2 ;;
		-role) role=$2 ;;
		-policy) policy=$2 ;;
		-audience) audience=$2 ;;
		-ttl) ttl=$2 ;;
		-kv) kv=$2 ;;
		-prefix) prefix=$2 ;;
		esac
		shift
		;;
	*) die "unknown option $1" ;;
	esac
	shift
done

name_re='^[A-Za-z0-9][A-Za-z0-9._-]*$'
path_re='^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$'
fqdn_re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
[[ $path =~ $path_re ]] || die "invalid -path $path"
[[ $policy =~ $name_re ]] || die "invalid -policy $policy"

seconds() {
	[[ $1 =~ ^([0-9]+)([smh]?)$ ]] || die "invalid -ttl $1 (e.g. 3600, 90m, 1h)"
	local n=${BASH_REMATCH[1]}
	case ${BASH_REMATCH[2]} in h) n=$((n * 3600)) ;; m) n=$((n * 60)) ;; esac
	[ "$n" -gt 0 ] || die "-ttl must be positive"
	echo "$n"
}

# The mount at -path as "vault auth list" reports it; empty if there is none.
# A mount of that name that this script did not create stops the run.
mount_json() {
	local m
	m=$("$VAULT" auth list -format=json | jq -c --arg p "$path/" '.[$p] // empty')
	if [ -n "$m" ] && ! jq -e --arg mark "$MARK" '.type == "jwt" and .description == $mark' <<<"$m" >/dev/null; then
		die "auth/$path exists and was not created by this script; choose another -path"
	fi
	printf '%s' "$m"
}

# The text of the policy; empty if there is none. A policy of that name that
# this script did not write stops the run.
policy_text() {
	local p
	"$VAULT" policy list -format=json | jq -e --arg p "$policy" 'index($p) != null' >/dev/null || return 0
	p=$("$VAULT" policy read "$policy")
	[ "$(head -n 1 <<<"$p")" = "$POLICY_MARK" ] || die "policy $policy exists and was not written by this script; choose another -policy"
	printf '%s' "$p"
}

confirm() {
	[ -n "$yes" ] && return 0
	[ -t 0 ] || die "stdin is not a terminal; pass -yes to proceed"
	local a
	read -r -p "$1 [y/N] " a
	case $a in y | Y | yes) ;; *) die "aborted" ;; esac
}

# show TITLE CURRENT DESIRED: print the change, return 1 if there is none.
show() {
	if [ "$2" = "$3" ]; then
		printf '= %s: unchanged\n' "$1"
		return 1
	fi
	if [ -z "$2" ]; then printf '+ %s: create\n' "$1"; else printf '~ %s: update\n' "$1"; fi
	diff -u --label current --label new <(printf '%s\n' "$2") <(printf '%s\n' "$3") | sed '1,2d;s/^/    /' || true
}

if [ "$cmd" = rollback ]; then
	echo "Vault: ${VAULT_ADDR:-unset}"
	m=$(mount_json)
	p=$(policy_text)
	[ -n "$m$p" ] || { echo "nothing to roll back"; exit 0; }
	[ -n "$m" ] && echo "- auth/$path: disable; revokes every token issued through it"
	[ -n "$p" ] && echo "- policy $policy: delete"
	confirm "Roll back?"
	[ -n "$m" ] && "$VAULT" auth disable "$path"
	[ -n "$p" ] && "$VAULT" policy delete "$policy"
	exit 0
fi

[ -n "$issuer" ] || die "-issuer is required"
[[ $domain =~ $fqdn_re ]] || die "-trust-domain is required (a DNS name)"
[ ${#keyfiles[@]} -gt 0 ] || die "-key is required, once per authority instance"
[[ $role =~ $name_re ]] || die "invalid -role $role"
[[ $kv =~ $path_re ]] || die "invalid -kv $kv"
[[ $prefix =~ $path_re ]] || die "invalid -prefix $prefix"
[ -n "$audience" ] || die "-audience must not be empty"
ttl_s=$(seconds "$ttl")
if [ -n "$all" ] && [ ${#identities[@]} -gt 0 ]; then
	die "-identity and -all-identities exclude each other"
elif [ -z "$all" ] && [ ${#identities[@]} -eq 0 ]; then
	die "name the admitted machines with -identity, or pass -all-identities"
fi

pems=()
for f in "${keyfiles[@]}"; do
	pem=$(cat "$f") || die "cannot read $f"
	grep -q -- '-----BEGIN PUBLIC KEY-----' <<<"$pem" || die "$f is not a PEM public key"
	grep -q -- 'PRIVATE KEY' <<<"$pem" && die "$f holds a private key; pass the public key"
	pems+=("$pem")
done

if [ -n "$all" ]; then
	claims_type=glob
	claims=$(jq -n --arg s "spiffe://$domain/host/*" '{sub: $s}')
else
	for i in "${identities[@]}"; do [[ $i =~ $fqdn_re ]] || die "invalid -identity $i"; done
	claims_type=string
	claims=$(printf "spiffe://$domain/host/%s\n" "${identities[@]}" | sort -u | jq -R . | jq -s '{sub: .}')
fi

# The KV mount must exist as version 2: the policy grants <kv>/data/...
kv_version=$("$VAULT" secrets list -format=json | jq -r --arg m "$kv/" '
	.[$m] | if . == null then "missing" elif .type == "kv" then (.options.version // "1") else .type end')
[ "$kv_version" = 2 ] || die "$kv/ must be a KV version 2 mount, found: $kv_version"

pubkeys=$(for p in "${pems[@]}"; do jq -Rs 'rtrimstr("\n")' <<<"$p"; done | jq -s .)
desired_config=$(jq -n -S --arg iss "$issuer" --argjson keys "$pubkeys" '{bound_issuer: $iss, jwt_validation_pubkeys: $keys}')
# Vault accepts a token until "exp" plus clock_skew_leeway (60 s);
# expiration_leeway is turned off so that nothing is added on top.
desired_role=$(jq -n -S --arg aud "$audience" --arg type "$claims_type" --argjson claims "$claims" \
	--argjson ttl "$ttl_s" --arg policy "$policy" '{
	role_type: "jwt",
	bound_audiences: [$aud],
	user_claim: "sub",
	bound_claims_type: $type,
	bound_claims: $claims,
	claim_mappings: {host: "host"},
	expiration_leeway: -1,
	token_ttl: $ttl,
	token_max_ttl: $ttl,
	token_policies: [$policy]
}')
desired_policy() { # accessor
	cat <<EOF
$POLICY_MARK
# A machine logged in through auth/$path reads the secrets below its own
# identity, the "host" claim of its token, and nothing else.
path "$kv/data/$prefix/{{identity.entity.aliases.$1.metadata.host}}/*" {
  capabilities = ["read"]
}
EOF
}

echo "Vault: ${VAULT_ADDR:-unset}"
changes=0
m=$(mount_json)
if [ -n "$m" ]; then
	accessor=$(jq -r .accessor <<<"$m")
	printf '= auth/%s: jwt, accessor %s\n' "$path" "$accessor"
	current_config=$("$VAULT" read -format=json "auth/$path/config" |
		jq -S '.data | {bound_issuer, jwt_validation_pubkeys: ((.jwt_validation_pubkeys // []) | map(sub("^\\s+"; "") | sub("\\s+$"; "")))}')
	current_role=""
	if "$VAULT" list -format=json "auth/$path/role" 2>/dev/null | jq -e --arg r "$role" 'index($r) != null' >/dev/null; then
		current_role=$("$VAULT" read -format=json "auth/$path/role/$role" | jq -S --argjson want "$desired_role" '.data | with_entries(select(.key as $k | $want | has($k)))')
	fi
else
	accessor="<accessor of auth/$path>"
	printf '+ auth/%s: enable jwt\n' "$path"
	changes=1
	current_config="" current_role=""
fi
current_policy=$(policy_text)
write_config="" write_role="" write_policy=""
show "auth/$path/config" "$current_config" "$desired_config" && write_config=1
show "auth/$path/role/$role" "$current_role" "$desired_role" && write_role=1
show "policy $policy" "$current_policy" "$(desired_policy "$accessor")" && write_policy=1
[ -n "$write_config$write_role$write_policy" ] && changes=1

if [ "$cmd" = plan ] || [ $changes -eq 0 ]; then
	[ $changes -eq 0 ] && echo "No changes."
	exit 0
fi

confirm "Apply these changes?"
if [ -z "$m" ]; then
	"$VAULT" auth enable -path="$path" -description="$MARK" jwt
	accessor=$(mount_json | jq -r .accessor)
fi
[ -n "$write_config" ] && "$VAULT" write "auth/$path/config" - <<<"$desired_config"
[ -n "$write_role" ] && "$VAULT" write "auth/$path/role/$role" - <<<"$desired_role"
[ -n "$write_policy" ] && desired_policy "$accessor" | "$VAULT" policy write "$policy" -
echo "Applied: auth/$path (accessor $accessor), role $role, policy $policy."
