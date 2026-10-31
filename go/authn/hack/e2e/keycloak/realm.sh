#!/usr/bin/env bash
# Sets up a Keycloak realm for the authn step-up e2e, through the admin REST
# API. Idempotent: it creates what is missing and updates what exists, so it
# also works on a shared, long-lived Keycloak.
#
#   realm.sh                       the whole setup (below)
#   realm.sh loa2-max-age <secs>   only set the LoA-2 condition's max age
#
# What it sets up in $REALM:
#   - realm attribute "ACR to LoA mapping" (acr.loa.map) = $ACR_LOA_MAP
#   - flow browser-stepup (Keycloak docs: "Creating a browser login flow with
#     step-up mechanism"):
#       Cookie                                   ALTERNATIVE
#       stepup-forms (generic subflow)           ALTERNATIVE
#         loa1 (subflow)                         CONDITIONAL
#           Condition - Level of Authentication  REQUIRED  level 1, max age 36000
#           Username Password Form               REQUIRED
#         loa2 (subflow)                         CONDITIONAL
#           Condition - Level of Authentication  REQUIRED  level 2, max age $LOA2_MAX_AGE
#           OTP Form                             REQUIRED
#   - confidential client $CLIENT_ID (standard flow only, redirect URI
#     $REDIRECT_URI, browser flow overridden to browser-stepup, a "groups"
#     claim mapper). The default "acr" client scope puts acr in the ID token.
#   - group $TEST_GROUP and user $TEST_USER in it, with a password and a TOTP
#     credential whose key is $TOTP_SEED. The user is deleted and recreated
#     on every run (a TOTP secret can't be read back or set on an existing
#     user), so use a dedicated test user.
#
# Env (required unless a default is shown):
#   KC_URL                 Keycloak base URL, e.g. http://keycloak.keycloak.svc:8080
#   KC_ADMIN_USER=admin    KC_ADMIN_PASSWORD   KC_ADMIN_REALM=master
#   KC_CURL_ARGS=          extra curl args for every Keycloak request (e.g. --connect-to h:p:127.0.0.1:p)
#   REALM=krateo           CLIENT_ID=portal    CLIENT_SECRET    REDIRECT_URI
#   TEST_USER=alice        TEST_PASSWORD       TOTP_SEED        TEST_GROUP=devs
#   ACR_LOA_MAP={"silver":1,"gold":2}          LOA2_MAX_AGE=0
#
# Needs bash, curl, jq.
set -euo pipefail

: "${KC_URL:?}" "${KC_ADMIN_PASSWORD:?}"
KC_ADMIN_USER=${KC_ADMIN_USER:-admin}
KC_ADMIN_REALM=${KC_ADMIN_REALM:-master}
REALM=${REALM:-krateo}
LOA2_MAX_AGE=${LOA2_MAX_AGE:-0}
read -ra CURL_X <<<"${KC_CURL_ARGS:-}"

kc() { curl -sS --fail-with-body "${CURL_X[@]}" "$@"; }
# A fresh admin token per call: admin-cli tokens live 60s by default.
adm() {
  local method=$1 path=$2 tok; shift 2
  tok=$(kc -d grant_type=password -d client_id=admin-cli --data-urlencode "username=$KC_ADMIN_USER" \
    --data-urlencode "password=$KC_ADMIN_PASSWORD" "$KC_URL/realms/$KC_ADMIN_REALM/protocol/openid-connect/token" | jq -r .access_token)
  kc -X "$method" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$KC_URL/admin/realms$path" "$@"
}
log() { echo "realm.sh: $*"; }

executions() { adm GET "/$REALM/authentication/flows/$1/executions"; }

# set_loa <subflow> <level> <max age>: creates or updates the subflow's
# "Condition - Level of Authentication" config.
set_loa() {
  local ex id cfg body
  ex=$(executions "$1" | jq -c 'map(select(.providerId=="conditional-level-of-authentication"))[0]')
  id=$(jq -r .id <<<"$ex"); cfg=$(jq -r '.authenticationConfig // empty' <<<"$ex")
  body=$(jq -nc --arg a "$1-condition" --arg l "$2" --arg m "$3" '{alias:$a, config:{"loa-condition-level":$l, "loa-max-age":$m}}')
  if [[ -n "$cfg" ]]; then adm PUT "/$REALM/authentication/config/$cfg" -d "$(jq -c --arg id "$cfg" '.id=$id' <<<"$body")" >/dev/null
  else adm POST "/$REALM/authentication/executions/$id/config" -d "$body" >/dev/null; fi
  log "$1: level $2, max age $3s"
}

if [[ "${1:-}" == loa2-max-age ]]; then
  set_loa loa2 2 "${2:?usage: realm.sh loa2-max-age <seconds>}"
  exit 0
fi

: "${CLIENT_SECRET:?}" "${REDIRECT_URI:?}" "${TEST_PASSWORD:?}" "${TOTP_SEED:?}"
CLIENT_ID=${CLIENT_ID:-portal}
TEST_USER=${TEST_USER:-alice}
TEST_GROUP=${TEST_GROUP:-devs}
ACR_LOA_MAP=${ACR_LOA_MAP:-'{"silver":1,"gold":2}'}

# --- realm and ACR-to-LoA mapping
if ! adm GET "/$REALM" >/dev/null 2>&1; then
  adm POST "" -d "$(jq -nc --arg r "$REALM" '{realm:$r, enabled:true}')" >/dev/null
  log "created realm $REALM"
fi
adm PUT "/$REALM" -d "$(jq -nc --arg m "$ACR_LOA_MAP" '{attributes:{"acr.loa.map":$m}}')" >/dev/null
log "acr.loa.map = $ACR_LOA_MAP"

# --- the step-up browser flow
has_exec() { executions "$1" | jq -e --arg p "$2" 'any(.[]; .providerId==$p or .displayName==$p)' >/dev/null; }
add_exec() { has_exec "$1" "$2" || adm POST "/$REALM/authentication/flows/$1/executions/execution" -d "{\"provider\":\"$2\"}" >/dev/null; }
add_flow() { has_exec "$1" "$2" || adm POST "/$REALM/authentication/flows/$1/executions/flow" \
  -d "{\"alias\":\"$2\",\"type\":\"basic-flow\",\"provider\":\"registration-page-form\",\"description\":\"\"}" >/dev/null; }
# require <flow> <providerId or subflow name> <REQUIREMENT>
require() {
  local e
  e=$(executions "$1" | jq -c --arg n "$2" 'map(select(.providerId==$n or .displayName==$n))[0]')
  [[ "$(jq -r .requirement <<<"$e")" == "$3" ]] || adm PUT "/$REALM/authentication/flows/$1/executions" -d "$(jq -c --arg r "$3" '.requirement=$r' <<<"$e")" >/dev/null
}
if ! adm GET "/$REALM/authentication/flows" | jq -e 'any(.[]; .alias=="browser-stepup")' >/dev/null; then
  adm POST "/$REALM/authentication/flows" \
    -d '{"alias":"browser-stepup","providerId":"basic-flow","topLevel":true,"builtIn":false,"description":"browser login with step-up (LoA 1 password, LoA 2 OTP)"}' >/dev/null
  log "created flow browser-stepup"
fi
add_exec browser-stepup auth-cookie;  require browser-stepup auth-cookie ALTERNATIVE
add_flow browser-stepup stepup-forms; require browser-stepup stepup-forms ALTERNATIVE
add_flow stepup-forms loa1;           require stepup-forms loa1 CONDITIONAL
add_flow stepup-forms loa2;           require stepup-forms loa2 CONDITIONAL
add_exec loa1 conditional-level-of-authentication; require loa1 conditional-level-of-authentication REQUIRED
add_exec loa1 auth-username-password-form;         require loa1 auth-username-password-form REQUIRED
add_exec loa2 conditional-level-of-authentication; require loa2 conditional-level-of-authentication REQUIRED
add_exec loa2 auth-otp-form;                       require loa2 auth-otp-form REQUIRED
set_loa loa1 1 36000
set_loa loa2 2 "$LOA2_MAX_AGE"
FLOW_ID=$(adm GET "/$REALM/authentication/flows" | jq -r '.[]|select(.alias=="browser-stepup").id')
executions browser-stepup | jq -r '.[] | "realm.sh:   \("  " * .level)\(.displayName)  \(.requirement)"'

# --- the client
CLIENT=$(jq -nc --arg c "$CLIENT_ID" --arg r "$REDIRECT_URI" --arg s "$CLIENT_SECRET" --arg f "$FLOW_ID" '{
  clientId:$c, enabled:true, protocol:"openid-connect", publicClient:false, clientAuthenticatorType:"client-secret", secret:$s,
  standardFlowEnabled:true, directAccessGrantsEnabled:false, implicitFlowEnabled:false, serviceAccountsEnabled:false,
  redirectUris:[$r], authenticationFlowBindingOverrides:{browser:$f}}')
CID=$(adm GET "/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id // empty')
if [[ -z "$CID" ]]; then
  adm POST "/$REALM/clients" -d "$CLIENT" >/dev/null
  CID=$(adm GET "/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
  log "created client $CLIENT_ID"
else
  adm PUT "/$REALM/clients/$CID" -d "$CLIENT" >/dev/null
  log "updated client $CLIENT_ID"
fi
if ! adm GET "/$REALM/clients/$CID/protocol-mappers/models" | jq -e 'any(.[]; .name=="groups")' >/dev/null; then
  adm POST "/$REALM/clients/$CID/protocol-mappers/models" -d '{"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper",
    "config":{"claim.name":"groups","full.path":"false","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}}' >/dev/null
fi
SCOPES=$(adm GET "/$REALM/clients/$CID/default-client-scopes" | jq -c 'map(.name)')
log "client $CLIENT_ID default scopes: $SCOPES"
jq -e 'index("acr")' <<<"$SCOPES" >/dev/null || { log "ERROR: the acr client scope is not a default scope of $CLIENT_ID, so ID tokens carry no acr"; exit 1; }

# --- group and user (recreated: see the header)
adm GET "/$REALM/groups?search=$TEST_GROUP&exact=true" | jq -e --arg g "$TEST_GROUP" 'any(.[]; .name==$g)' >/dev/null \
  || adm POST "/$REALM/groups" -d "$(jq -nc --arg g "$TEST_GROUP" '{name:$g}')" >/dev/null
OLD=$(adm GET "/$REALM/users?username=$TEST_USER&exact=true" | jq -r '.[0].id // empty')
[[ -n "$OLD" ]] && adm DELETE "/$REALM/users/$OLD" >/dev/null
adm POST "/$REALM/users" -d "$(jq -nc --arg u "$TEST_USER" --arg pw "$TEST_PASSWORD" --arg seed "$TOTP_SEED" --arg g "/$TEST_GROUP" '{
  username:$u, enabled:true, email:"\($u)@example.com", emailVerified:true, firstName:$u, lastName:"E2E",
  groups:[$g],
  credentials:[{type:"password", value:$pw, temporary:false},
    {type:"otp", userLabel:"e2e", secretData:({value:$seed}|tojson),
     credentialData:({subType:"totp", digits:6, counter:0, period:30, algorithm:"HmacSHA1"}|tojson)}]}')" >/dev/null
USER_ID=$(adm GET "/$REALM/users?username=$TEST_USER&exact=true" | jq -r '.[0].id')
CREDS=$(adm GET "/$REALM/users/$USER_ID/credentials" | jq -c 'map(.type)|sort')
GROUPS_=$(adm GET "/$REALM/users/$USER_ID/groups" | jq -c 'map(.name)')
log "user $TEST_USER: credentials $CREDS, groups $GROUPS_"
[[ "$CREDS" == '["otp","password"]' ]] || { log "ERROR: $TEST_USER should have a password and an OTP credential"; exit 1; }
jq -e --arg g "$TEST_GROUP" 'index($g)' <<<"$GROUPS_" >/dev/null || { log "ERROR: $TEST_USER is not in $TEST_GROUP"; exit 1; }
log "done"
