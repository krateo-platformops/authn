#!/usr/bin/env bash
# "cond && pass || fail" is used on purpose: pass always returns 0.
# shellcheck disable=SC2015
# The name guard e2e against a real Keycloak and a real apiserver: authn
# issues a username only to the identity it was issued to, and an identity
# source can't take a name the cluster already grants rights to.
#
# Scenarios (each with its own Keycloak user, created by realm.sh):
#   g0  the user stepup.sh signed in has a claim ["oidc", <iss>, <sub>]
#   g1  a name a ClusterRoleBinding names as a User -> 403 UsernameUnavailable, no Secret
#   g2  the binding removed -> 200, and the claim names that Keycloak user
#   g3  the Keycloak user deleted and re-created (new sub, same name) -> 403, claim unchanged
#   g4  a user in Keycloak group system:nodes -> 403 SystemGroupNotAllowed, no Secret
#   g5  a reserved name (kube-guard-e2e) -> 403 UsernameUnavailable, no Secret
#   log authn logs "username refused" for g1, g3 and g5
#
# Env: as stepup.sh (AUTHN_URL, TEST_PASSWORD, TOTP_SEED, KC_CURL_ARGS, OIDC_NAME),
# plus realm.sh's admin env (KC_URL, KC_ADMIN_USER, KC_ADMIN_PASSWORD, REALM), and
# kubectl access to AUTHN_NAMESPACE (Secrets, pod logs) and to create and delete
# one ClusterRoleBinding (guard-e2e-bound).
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
: "${AUTHN_URL:?}" "${TEST_PASSWORD:?}" "${TOTP_SEED:?}" "${KC_URL:?}" "${REALM:?}"
OIDC_NAME=${OIDC_NAME:-keycloak}
TEST_USER=${TEST_USER:-alice}
AUTHN_NAMESPACE=${AUTHN_NAMESPACE:-krateo-system}
W=${WORKDIR:-$(mktemp -d)}
mkdir -p "$W"
# shellcheck disable=SC2034 # read by lib.sh (kc)
read -ra CURL_X <<<"${KC_CURL_ARGS:-}"
FAILS=()
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$HERE/lib.sh"

claim() { kubectl -n "$AUTHN_NAMESPACE" get secret "$1-clientconfig" --ignore-not-found -o jsonpath='{.metadata.annotations.authn\.krateo\.io/claim}'; }
has_secret() { [[ -n "$(kubectl -n "$AUTHN_NAMESPACE" get secret "$1-clientconfig" --ignore-not-found -o name)" ]]; }
kc_user_id() { # the Keycloak id of user $1, which Keycloak issues as sub
  local tok
  tok=$(kc -s -X POST "$KC_URL/realms/${KC_ADMIN_REALM:-master}/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d "username=${KC_ADMIN_USER:-admin}" --data-urlencode "password=$KC_ADMIN_PASSWORD" | jq -r .access_token)
  kc -s -H "Authorization: Bearer $tok" "$KC_URL/admin/realms/$REALM/users?username=$1&exact=true" | jq -r '.[0].id // empty'
}
# signin <user> <response file>: a fresh browser session for user, through
# authCodeURL, then /oidc/login. Sets C to the HTTP code. It runs in this shell,
# not a subshell, so next_otp never reuses a TOTP window (Keycloak refuses that).
signin() {
  rm -f "$W/j-$1"
  local saved=$TEST_USER; TEST_USER=$1
  if authorize "$W/j-$1" "$(login_url "$OIDC_NAME")" >"$W/authorize-$1.log"; then
    C=$(login "$OIDC_NAME" "$CODE" "$2")
  else
    C=authorize-failed; cat "$W/authorize-$1.log"
  fi
  TEST_USER=$saved
}
new_user() { TEST_USER=$1 TEST_GROUP=${2:-devs} "$HERE/realm.sh" >/dev/null || fail "realm.sh $1"; }

EXT=$(strategy "$OIDC_NAME")
# shellcheck disable=SC2034 # read by lib.sh (authorize)
REDIRECT_URI=$(jq -r '.redirectURL' <<<"$EXT")
ISS=$(kc -s "$KC_URL/realms/$REALM/.well-known/openid-configuration" | jq -r .issuer)

step "g0. $TEST_USER's claim"
want=$(jq -nc --arg i "$ISS" --arg s "$(kc_user_id "$TEST_USER")" '["oidc",$i,$s]')
[[ "$(claim "$TEST_USER")" == "$want" ]] && pass "g0: claim $want" || fail "g0: claim '$(claim "$TEST_USER")', want $want"

U=guard-bound
step "g1. $U is a User subject of a ClusterRoleBinding"
kubectl delete clusterrolebinding guard-e2e-bound --ignore-not-found >/dev/null
kubectl create clusterrolebinding guard-e2e-bound --clusterrole=view --user="$U" >/dev/null || fail "g1: create the binding"
new_user "$U"
signin "$U" "$W/r-g1.json"
[[ "$C" == 403 && "$(reason "$W/r-g1.json")" == UsernameUnavailable ]] && pass "g1: 403 UsernameUnavailable" || fail "g1: $C $(cat "$W/r-g1.json")"
has_secret "$U" && fail "g1: a Secret was written" || pass "g1: no Secret"

step "g2. the binding removed"
kubectl delete clusterrolebinding guard-e2e-bound >/dev/null
signin "$U" "$W/r-g2.json"
[[ "$C" == 200 ]] && pass "g2: 200" || fail "g2: $C $(cat "$W/r-g2.json")"
CLAIM_G2=$(jq -nc --arg i "$ISS" --arg s "$(kc_user_id "$U")" '["oidc",$i,$s]')
[[ "$(claim "$U")" == "$CLAIM_G2" ]] && pass "g2: claim $CLAIM_G2" || fail "g2: claim '$(claim "$U")', want $CLAIM_G2"

step "g3. $U deleted and re-created in Keycloak: same name, new sub"
new_user "$U"
[[ "$(kc_user_id "$U")" != "$(jq -r '.[2]' <<<"$CLAIM_G2")" ]] && pass "g3: Keycloak gave $U a new id" || fail "g3: same Keycloak id"
signin "$U" "$W/r-g3.json"
[[ "$C" == 403 && "$(reason "$W/r-g3.json")" == UsernameUnavailable ]] && pass "g3: 403 UsernameUnavailable" || fail "g3: $C $(cat "$W/r-g3.json")"
[[ "$(claim "$U")" == "$CLAIM_G2" ]] && pass "g3: claim unchanged" || fail "g3: claim now '$(claim "$U")'"

U4=guard-sys
step "g4. $U4 is in the Keycloak group system:nodes"
new_user "$U4" "system:nodes"
signin "$U4" "$W/r-g4.json"
[[ "$C" == 403 && "$(reason "$W/r-g4.json")" == SystemGroupNotAllowed ]] && pass "g4: 403 SystemGroupNotAllowed" || fail "g4: $C $(cat "$W/r-g4.json")"
has_secret "$U4" && fail "g4: a Secret was written" || pass "g4: no Secret"

U5=kube-guard-e2e
step "g5. $U5 is reserved"
new_user "$U5"
signin "$U5" "$W/r-g5.json"
[[ "$C" == 403 && "$(reason "$W/r-g5.json")" == UsernameUnavailable ]] && pass "g5: 403 UsernameUnavailable" || fail "g5: $C $(cat "$W/r-g5.json")"
has_secret "$U5" && fail "g5: a Secret was written" || pass "g5: no Secret"

step "log: authn says why"
REFUSED=$(kubectl -n "$AUTHN_NAMESPACE" logs deploy/authn --tail=-1 | jq -Rc 'fromjson? | select(.message=="username refused") | {username, reason}' | sort -u)
echo "$REFUSED"
for u in "$U" "$U5"; do
  grep -q "\"username\":\"$u\"" <<<"$REFUSED" && pass "log: $u refused, with a reason" || fail "log: no 'username refused' line for $u"
done

echo
if (( ${#FAILS[@]} )); then printf 'FAILED (%d):\n' "${#FAILS[@]}"; printf '  %s\n' "${FAILS[@]}"; exit 1; fi
echo "ALL PASSED"
