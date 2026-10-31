#!/usr/bin/env bash
# "cond && pass || fail" is used on purpose: pass always returns 0.
# shellcheck disable=SC2015
# The authn step-up e2e against a real Keycloak set up by realm.sh. It drives
# Keycloak's login pages with curl like a browser (cookie jar, form actions,
# TOTP computed here), starting from the URLs authn's /strategies advertises,
# as the portal does: extensions.authCodeURL for a login and
# extensions.stepUpAuthCodeURL for a step-up. Then it posts the code to authn
# and checks the answer.
#
# Scenarios:
#   strategies  the advertised URLs (state printable, step-up URL carries acr_values and max_age)
#   probe       the ID-token claims Keycloak issues (codes exchanged here; needs CLIENT_SECRET)
#   a           login -> /oidc/login 200
#   c           a login code -> /oidc/stepup 403 InsufficientAssurance
#   b           stepUpAuthCodeURL in the user's session -> /oidc/stepup 200, krateo:loa:2
#   d           session older than maxAge: acr_values alone (no max_age) asks only the OTP
#               and gets a fresh auth_time (LoA-2 max age 0); stepUpAuthCodeURL -> 200
#   e           LoA-2 max age 300s (> maxAge; needs the Keycloak admin env, see realm.sh):
#               acr_values alone is answered from SSO with the old auth_time -> 403
#               StaleAuthentication; stepUpAuthCodeURL (max_age) -> re-authentication -> 200
# d and e deliberately drop max_age from stepUpAuthCodeURL to show what it
# prevents. They wait maxAge+15s of OIDC_NAME_STALE, so give that OIDCConfig a
# short maxAge (kind.sh uses 60s).
#
# Env (required unless a default is shown):
#   AUTHN_URL                 e.g. http://authn.krateo-system.svc:8082
#   OIDC_NAME=keycloak        the OIDCConfig (with spec.stepUp) under test
#   OIDC_NAME_STALE=$OIDC_NAME   the OIDCConfig for d and e: same Keycloak client, a short stepUp.maxAge
#   TEST_USER=alice           TEST_PASSWORD             TOTP_SEED
#   KC_CURL_ARGS=             extra curl args for every Keycloak request (kind: --connect-to)
#   CLIENT_ID=portal  CLIENT_SECRET=   to print the ID-token claims (probe); skipped when unset
#   KC_ADMIN_PASSWORD=        enables scenario e (also KC_URL, KC_ADMIN_USER, KC_ADMIN_REALM, REALM: see realm.sh)
#   SKIP=                     scenarios to skip, e.g. "d e"
#   KUBECTL_CHECKS=0          1: also check the Secrets with kubectl (needs get on Secrets in AUTHN_NAMESPACE)
#   AUTHN_NAMESPACE=krateo-system
#   WORKDIR=$(mktemp -d)      cookie jars and responses
#
# Needs bash 4.4+, curl, jq, openssl (TOTP is HMAC-SHA1 via openssl dgst), and
# od, sed, awk, base64. kubectl only with KUBECTL_CHECKS=1.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
: "${AUTHN_URL:?}" "${TEST_PASSWORD:?}" "${TOTP_SEED:?}"
OIDC_NAME=${OIDC_NAME:-keycloak}
OIDC_NAME_STALE=${OIDC_NAME_STALE:-$OIDC_NAME}
TEST_USER=${TEST_USER:-alice}
CLIENT_ID=${CLIENT_ID:-portal}
CLIENT_SECRET=${CLIENT_SECRET:-}
SKIP=${SKIP:-}
KUBECTL_CHECKS=${KUBECTL_CHECKS:-0}
AUTHN_NAMESPACE=${AUTHN_NAMESPACE:-krateo-system}
W=${WORKDIR:-$(mktemp -d)}
mkdir -p "$W"
read -ra CURL_X <<<"${KC_CURL_ARGS:-}"

FAILS=()
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILS+=("$*"); }
info() { echo "INFO $*"; }
step() { printf '\n===== %s  [%s]\n' "$*" "$(date -u +%H:%M:%S)"; }
skip() { [[ " $SKIP " == *" $1 "* ]] && { echo "SKIP scenario $1"; return 0; }; return 1; }
b64url() { local p; p=$(tr '_-' '/+' <<<"$1"); while (( ${#p} % 4 )); do p="$p="; done; base64 -d <<<"$p" 2>/dev/null; }
jwt() { b64url "$(cut -d. -f2 <<<"$1")"; }
kc() { curl -sS "${CURL_X[@]}" "$@"; }
qparam() { sed -nE "s/.*[?&]$2=([^&]*).*/\\1/p" <<<"$1"; }
drop_max_age() { sed -E 's/([?&])max_age=[^&]*&?/\1/; s/[?&]$//' <<<"$1"; }

# --- authn
strategy() { curl -sS "$AUTHN_URL/strategies" | jq -c --arg n "$1" '.[] | select(.kind=="oidc" and .name==$n) | .extensions'; }
login_url()  { strategy "$1" | jq -r '.authCodeURL // empty'; }
stepup_url() { strategy "$1" | jq -r '.stepUpAuthCodeURL // empty'; }
login()  { curl -sS -o "$3" -w '%{http_code}' -H "X-Auth-Code: $2" "$AUTHN_URL/oidc/login?name=$1"; }
stepup() { curl -sS -o "$3" -w '%{http_code}' -X POST -H "X-Auth-Code: $2" "$AUTHN_URL/oidc/stepup?name=$1"; }
reason() { jq -r '.details.causes[0].reason // empty' "$1" 2>/dev/null; }
message() { jq -r '.message // empty' "$1" 2>/dev/null; }

# --- TOTP (RFC 6238, SHA1, 6 digits, 30s), key = the raw bytes of TOTP_SEED
# as Keycloak stores them. Keycloak refuses a code reused in its window, so
# every OTP form gets a code from a window not used before.
LAST_STEP=0
totp_code() { # <seed> <time step>
  local key mac off
  key=$(printf '%s' "$1" | od -An -tx1 | tr -d ' \n')
  # shellcheck disable=SC2059 # the format is the counter as \xNN escapes
  mac=$(printf "$(printf '%016x' "$2" | sed 's/../\\x&/g')" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$key" | awk '{print $NF}')
  off=$(( 16#${mac:39:1} ))
  printf '%06d' $(( (16#${mac:off*2:8} & 0x7fffffff) % 1000000 ))
}
next_otp() { # sets OTP
  local now s; now=$(date +%s); s=$(( now / 30 ))
  if (( s <= LAST_STEP )); then sleep $(( (LAST_STEP + 1) * 30 - now + 1 )); s=$(( $(date +%s) / 30 )); fi
  LAST_STEP=$s; OTP=$(totp_code "$TOTP_SEED" "$s")
}

# authorize <jar> <authorization URL>: follows Keycloak like a browser (no -L,
# every hop looked at), filling the password and OTP forms. Sets CODE, and
# PAGES = the forms shown ("password,otp", "otp"; "sso" when none).
authorize() {
  local jar=$1 n=0 hdr=$W/h.txt body=$W/b.html loc action page
  CODE=""; PAGES=""
  kc -b "$jar" -c "$jar" -D "$hdr" -o "$body" "$2"
  while (( n++ < 8 )); do
    loc=$(sed -nE 's/^[Ll]ocation: (.*)$/\1/p' "$hdr" | tr -d '\r')
    if [[ -n "$loc" ]]; then
      if [[ "$loc" == "$REDIRECT_URI"* ]]; then
        CODE=$(qparam "$loc" code); PAGES=${PAGES:-sso}
        [[ -n "$CODE" ]] && return 0
        echo "  redirected back without a code: $loc"; return 1
      fi
      kc -b "$jar" -c "$jar" -D "$hdr" -o "$body" "$loc"; continue
    fi
    action=$(grep -oE '<form[^>]*action="[^"]*"' "$body" | head -1 | sed -E 's/.*action="([^"]*)".*/\1/; s/&amp;/\&/g')
    if grep -q 'name="otp"' "$body"; then page=otp
    elif grep -q 'name="password"' "$body"; then page=password
    else
      echo "  unexpected page ($(head -1 "$hdr" | tr -d '\r')): $(grep -oE '<title>[^<]*' "$body" | head -1)"
      grep -oE '(kc-feedback-text|instruction|alert)[^>]*>[^<]+' "$body" | head -3; return 1
    fi
    if [[ ",$PAGES," == *",$page,"* ]]; then
      echo "  $page form shown again (refused?): $(grep -oE '(input-error|kc-feedback-text|alert)[^>]*>[^<]+' "$body" | head -2 | tr '\n' ' ')"; return 1
    fi
    PAGES="${PAGES:+$PAGES,}$page"
    if [[ $page == otp ]]; then next_otp; kc -b "$jar" -c "$jar" -D "$hdr" -o "$body" --data-urlencode "otp=$OTP" "$action"
    else kc -b "$jar" -c "$jar" -D "$hdr" -o "$body" --data-urlencode "username=$TEST_USER" \
      --data-urlencode "password=$TEST_PASSWORD" --data-urlencode credentialId= "$action"; fi
  done
  echo "  too many hops"; return 1
}

# claims <code>: the ID token's claims, from a code exchanged here (not by authn).
TOKEN_URL=""
claims() {
  local t
  [[ -z "$CLIENT_SECRET" || -z "${1:-}" ]] && { echo '{}'; return; }
  t=$(kc -d grant_type=authorization_code --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "client_secret=$CLIENT_SECRET" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" --data-urlencode "code=$1" "$TOKEN_URL" | jq -r '.id_token // empty')
  [[ -z "$t" ]] && { echo '{"error":"no id_token"}'; return; }
  jwt "$t" | jq -c --argjson now "$(date +%s)" '{acr, auth_time, age:($now - .auth_time), iat, iss, aud, azp, preferred_username, groups, sid}'
}
# probe <label> <jar> <url>: authorize, exchange the code here, print the claims.
probe() {
  [[ -z "$CLIENT_SECRET" ]] && return 0
  authorize "$2" "$3" || { fail "$1: authorize"; return 1; }
  echo "$1 pages=$PAGES claims=$(claims "$CODE" | tee "$W/claims-$1.json")"
}

secret_rv() { kubectl -n "$AUTHN_NAMESPACE" get secret "$1" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null; }
secret_cert() { kubectl -n "$AUTHN_NAMESPACE" get secret "$1" -o jsonpath='{.data.client-certificate-data}' | base64 -d | base64 -d; }
dns1123() { tr '[:upper:]' '[:lower:]' <<<"$1" | sed -E 's/[^a-z0-9.-]+/-/g'; }
SESSION_SECRET=$(dns1123 "$TEST_USER")-clientconfig
STEPUP_SECRET=$SESSION_SECRET-stepup

########################################################################
step "strategies: the URLs authn advertises for $OIDC_NAME and $OIDC_NAME_STALE"
EXT=$(strategy "$OIDC_NAME")
[[ -n "$EXT" ]] || { fail "no oidc strategy $OIDC_NAME at $AUTHN_URL/strategies"; exit 1; }
echo "$EXT" | jq .
LOGIN_URL=$(jq -r '.authCodeURL // empty' <<<"$EXT")
STEPUP_URL=$(jq -r '.stepUpAuthCodeURL // empty' <<<"$EXT")
if [[ -z "$STEPUP_URL" ]]; then
  fail "$OIDC_NAME advertises no extensions.stepUpAuthCodeURL: this authn predates the step-up hints in /strategies (authn#58), or spec.stepUp is missing or invalid (see the authn log). Not composing the URL: that is authn's contract."
  exit 1
fi
REDIRECT_URI=$(jq -r '.redirectURL' <<<"$EXT")
MAX_AGE=$(jq -r '.stepUpMaxAge' <<<"$EXT")
ACR_VALUES=$(jq -r '.stepUpAcrValues' <<<"$EXT")
[[ "$(jq -r .stepUpPath <<<"$EXT")" == /oidc/stepup ]] && pass "stepUpPath is /oidc/stepup" || fail "stepUpPath $(jq -r .stepUpPath <<<"$EXT")"
[[ "$(qparam "$STEPUP_URL" max_age)" == "$MAX_AGE" && -n "$MAX_AGE" ]] \
  && pass "stepUpAuthCodeURL carries max_age=$MAX_AGE (= stepUpMaxAge)" || fail "stepUpAuthCodeURL max_age '$(qparam "$STEPUP_URL" max_age)' vs stepUpMaxAge '$MAX_AGE'"
[[ "$(qparam "$STEPUP_URL" acr_values | sed 's/+/ /g; s/%20/ /g')" == "$ACR_VALUES" && -n "$ACR_VALUES" ]] \
  && pass "stepUpAuthCodeURL carries acr_values=$ACR_VALUES" || fail "stepUpAuthCodeURL acr_values '$(qparam "$STEPUP_URL" acr_values)'"
KEPT=1; for k in client_id redirect_uri response_type scope state; do [[ "$(qparam "$STEPUP_URL" $k)" == "$(qparam "$LOGIN_URL" $k)" ]] || KEPT=0; done
(( KEPT )) && pass "stepUpAuthCodeURL keeps authCodeURL's parameters" || fail "stepUpAuthCodeURL lost parameters of authCodeURL"
GOLD=${ACR_VALUES%% *}
BAD=0; for _ in $(seq 1 200); do
  s=$(qparam "$(login_url "$OIDC_NAME")" state)
  [[ "$s" =~ ^[A-Za-z0-9_-]{43}$ ]] || { BAD=$((BAD+1)); info "state not base64url(32 bytes): $s"; }
done
(( BAD == 0 )) && pass "state is base64url(32 bytes), no NUL, in 200/200 authCodeURLs" || fail "$BAD/200 authCodeURLs have a raw-bytes state (Keycloak answers 400 to a NUL in state)"
TOKEN_URL=${LOGIN_URL%%\?*}; TOKEN_URL=${TOKEN_URL%/auth}/token
STALE_MAX_AGE=$(strategy "$OIDC_NAME_STALE" | jq -r '.stepUpMaxAge // empty')
echo "token endpoint (probes): $TOKEN_URL; $OIDC_NAME_STALE maxAge: ${STALE_MAX_AGE:-none}s"

########################################################################
step "probe: the claims Keycloak issues (codes exchanged here, not by authn)"
if [[ -z "$CLIENT_SECRET" ]]; then echo "SKIP no CLIENT_SECRET"; else
  rm -f "$W"/j-*
  probe login "$W/j-p1" "$(login_url "$OIDC_NAME")"
  probe stepup "$W/j-p2" "$(stepup_url "$OIDC_NAME")"
  for f in login stepup; do
    c=$W/claims-$f.json
    [[ "$(jq -r .iss "$c")" == "${TOKEN_URL%/protocol/openid-connect/token}" ]] && pass "$f: iss is the realm issuer" || fail "$f: iss $(jq -r .iss "$c")"
    [[ "$(jq -r .auth_time "$c")" != null ]] && pass "$f: auth_time present" || fail "$f: no auth_time"
    [[ "$(jq -r .azp "$c")" == "$CLIENT_ID" ]] && pass "$f: azp is $CLIENT_ID" || fail "$f: azp $(jq -r .azp "$c")"
  done
  [[ "$(jq -r .acr "$W/claims-stepup.json")" == "$GOLD" ]] && pass "stepUpAuthCodeURL yields acr=$GOLD" || fail "step-up acr $(jq -r .acr "$W/claims-stepup.json")"
  [[ "$(jq -r .acr "$W/claims-login.json")" != "$GOLD" ]] && pass "a plain login yields acr=$(jq -r .acr "$W/claims-login.json"), not $GOLD" || fail "plain login acr is $GOLD"
fi

########################################################################
JAR=$W/j-session
if ! skip a; then
step "a. login: authCodeURL -> /oidc/login"
authorize "$JAR" "$(login_url "$OIDC_NAME")" || fail "a: authorize"
echo "pages=$PAGES"
C=$(login "$OIDC_NAME" "$CODE" "$W/r-a.json")
[[ "$C" == 200 ]] && pass "a: /oidc/login 200" || { fail "a: /oidc/login $C $(cat "$W/r-a.json")"; }
P=$(jwt "$(jq -r '.accessToken // empty' "$W/r-a.json")")
echo "a: user=$(jq -c .user "$W/r-a.json") groups=$(jq -c .groups "$W/r-a.json") jwt.groups=$(jq -c .groups <<<"$P" 2>/dev/null)"
[[ "$(jq -r .user.username "$W/r-a.json")" == "$TEST_USER" ]] && pass "a: user is $TEST_USER" || fail "a: user $(jq -c .user "$W/r-a.json")"
jq -e 'has("data")' "$W/r-a.json" >/dev/null && pass "a: response has the kubeconfig (data)" || fail "a: no data in the login response"
jq -e '.groups | index("krateo:loa:2") | not' <<<"$P" >/dev/null && pass "a: session JWT has no krateo:loa:2" || fail "a: session JWT groups $(jq -c .groups <<<"$P")"
if (( KUBECTL_CHECKS )); then
  RV0=$(secret_rv "$SESSION_SECRET")
  [[ -n "$RV0" ]] && pass "a: Secret $SESSION_SECRET exists" || fail "a: no Secret $SESSION_SECRET"
  SUBJ=$(secret_cert "$SESSION_SECRET" | openssl x509 -noout -subject -nameopt RFC2253)
  echo "a: session cert $SUBJ"
  [[ "$SUBJ" != *krateo:loa:2* ]] && pass "a: session cert has no krateo:loa:2" || fail "a: session cert $SUBJ"
fi
fi

########################################################################
if ! skip c; then
step "c. a login code (authCodeURL, no acr_values) -> /oidc/stepup"
authorize "$W/j-c" "$(login_url "$OIDC_NAME")" || fail "c: authorize"
C=$(stepup "$OIDC_NAME" "$CODE" "$W/r-c.json"); R=$(reason "$W/r-c.json")
[[ "$C" == 403 && "$R" == InsufficientAssurance ]] && pass "c: 403 InsufficientAssurance ($(message "$W/r-c.json"))" || fail "c: $C $R $(cat "$W/r-c.json")"
fi

########################################################################
if ! skip b; then
step "b. step-up: stepUpAuthCodeURL in the user's session -> /oidc/stepup"
authorize "$JAR" "$(stepup_url "$OIDC_NAME")" || fail "b: authorize"
echo "pages=$PAGES"
[[ "$PAGES" == *otp* ]] && pass "b: Keycloak asked for the OTP ($PAGES)" || fail "b: no OTP asked ($PAGES)"
C=$(stepup "$OIDC_NAME" "$CODE" "$W/r-b.json")
[[ "$C" == 200 ]] && pass "b: /oidc/stepup 200" || fail "b: /oidc/stepup $C $(cat "$W/r-b.json")"
KEYS=$(jq -c keys "$W/r-b.json")
[[ "$KEYS" == '["accessToken","groups","user"]' ]] && pass "b: response keys $KEYS (no data)" || fail "b: keys $KEYS"
TOKEN=$(jq -r '.accessToken // empty' "$W/r-b.json"); P=$(jwt "$TOKEN")
echo "b: jwt $(jq -c '{sub,groups,iat,exp}' <<<"$P" 2>/dev/null) header $(b64url "$(cut -d. -f1 <<<"$TOKEN")" | jq -c . 2>/dev/null)"
jq -e '.groups | index("krateo:loa:2")' <<<"$P" >/dev/null && pass "b: JWT groups include krateo:loa:2" || fail "b: JWT groups $(jq -c .groups <<<"$P" 2>/dev/null)"
jq -e '.groups | index("krateo:loa:2")' "$W/r-b.json" >/dev/null && pass "b: response groups include krateo:loa:2" || fail "b: response groups $(jq -c .groups "$W/r-b.json")"
[[ "$(b64url "$(cut -d. -f1 <<<"$TOKEN")" | jq -r .alg 2>/dev/null)" == RS256 ]] && pass "b: JWT is RS256" || fail "b: JWT alg"
EXP=$(jq -r .exp <<<"$P" 2>/dev/null); IAT=$(jq -r .iat <<<"$P" 2>/dev/null)
echo "b: JWT lifetime $(( (EXP - IAT) / 60 ))m$(( (EXP - IAT) % 60 ))s"
if (( KUBECTL_CHECKS )); then
  SUBJ=$(secret_cert "$STEPUP_SECRET" | openssl x509 -noout -subject -nameopt RFC2253)
  echo "b: step-up cert $SUBJ"
  [[ "$SUBJ" == *O=krateo:loa:2* ]] && pass "b: Secret $STEPUP_SECRET cert has O=krateo:loa:2" || fail "b: $STEPUP_SECRET cert $SUBJ"
  # exp <= notAfter, without parsing dates: the cert must still be valid at exp-1.
  secret_cert "$STEPUP_SECRET" | openssl x509 -noout -checkend $(( EXP - $(date +%s) - 1 )) >/dev/null \
    && pass "b: JWT exp <= cert notAfter" || fail "b: JWT exp $EXP outlives the step-up cert ($(secret_cert "$STEPUP_SECRET" | openssl x509 -noout -enddate))"
  if ! skip a; then
    RV1=$(secret_rv "$SESSION_SECRET")
    [[ "$RV0" == "$RV1" ]] && pass "b: $SESSION_SECRET untouched (resourceVersion $RV0)" || fail "b: $SESSION_SECRET resourceVersion $RV0 -> $RV1"
  fi
fi
fi

########################################################################
# stale <label>: wait until a session authenticated just now is older than OIDC_NAME_STALE's maxAge.
stale_wait() { echo "waiting $(( STALE_MAX_AGE + 15 ))s: older than $OIDC_NAME_STALE's maxAge ($STALE_MAX_AGE s)"; sleep $(( STALE_MAX_AGE + 15 )); }

if ! skip d; then
step "d. session older than maxAge, LoA-2 max age 0: acr_values alone, then stepUpAuthCodeURL ($OIDC_NAME_STALE)"
J=$W/j-d
authorize "$J" "$(login_url "$OIDC_NAME_STALE")" || fail "d: login"
echo "d0 login pages=$PAGES"
stale_wait
ACR_ONLY=$(drop_max_age "$(stepup_url "$OIDC_NAME_STALE")")
probe d1-acr-only "$J" "$ACR_ONLY"
authorize "$J" "$(drop_max_age "$(stepup_url "$OIDC_NAME_STALE")")" || fail "d2: authorize"
C=$(stepup "$OIDC_NAME_STALE" "$CODE" "$W/r-d2.json")
echo "d2 acr_values only -> authn: pages=$PAGES HTTP $C $(reason "$W/r-d2.json")"
[[ "$PAGES" == otp ]] && pass "d: Keycloak asks only for the OTP on an SSO step-up" || info "d: pages=$PAGES"
[[ "$C" == 200 ]] && pass "d: acr_values alone on an old session -> 200 (the OTP refreshes auth_time)" || fail "d: acr_values alone -> $C $(reason "$W/r-d2.json") $(message "$W/r-d2.json")"
authorize "$J" "$(stepup_url "$OIDC_NAME_STALE")" || fail "d3: authorize"
C=$(stepup "$OIDC_NAME_STALE" "$CODE" "$W/r-d3.json")
echo "d3 stepUpAuthCodeURL -> authn: pages=$PAGES HTTP $C $(reason "$W/r-d3.json")"
[[ "$C" == 200 ]] && pass "d: stepUpAuthCodeURL -> 200" || fail "d: stepUpAuthCodeURL -> $C $(reason "$W/r-d3.json")"
fi

########################################################################
if ! skip e; then
step "e. LoA-2 max age 300s (> $OIDC_NAME_STALE maxAge): acr_values alone vs stepUpAuthCodeURL"
if [[ -z "${KC_ADMIN_PASSWORD:-}" ]]; then echo "SKIP e: needs the Keycloak admin env (KC_URL, KC_ADMIN_PASSWORD) to change the LoA-2 max age"
elif (( STALE_MAX_AGE >= 300 )); then echo "SKIP e: $OIDC_NAME_STALE maxAge ${STALE_MAX_AGE}s is not below the 300s LoA-2 max age"
else
  "$HERE/realm.sh" loa2-max-age 300 || fail "e: set LoA-2 max age 300"
  trap '"$HERE/realm.sh" loa2-max-age 0 >/dev/null || echo "WARN: LoA-2 max age left at 300s; run realm.sh loa2-max-age 0"' EXIT
  J=$W/j-e
  authorize "$J" "$(stepup_url "$OIDC_NAME_STALE")" || fail "e0: authorize"
  echo "e0 step-up pages=$PAGES"
  stale_wait
  probe e1-acr-only "$J" "$(drop_max_age "$(stepup_url "$OIDC_NAME_STALE")")"
  authorize "$J" "$(drop_max_age "$(stepup_url "$OIDC_NAME_STALE")")" || fail "e2: authorize"
  C=$(stepup "$OIDC_NAME_STALE" "$CODE" "$W/r-e2.json"); R=$(reason "$W/r-e2.json")
  echo "e2 acr_values only -> authn: pages=$PAGES HTTP $C $R $(message "$W/r-e2.json")"
  [[ "$PAGES" == sso && "$C" == 403 && "$R" == StaleAuthentication ]] \
    && pass "e: acr_values alone is answered from SSO (old auth_time) -> 403 StaleAuthentication" \
    || fail "e: acr_values alone -> pages=$PAGES $C $R (expected sso, 403 StaleAuthentication)"
  authorize "$J" "$(stepup_url "$OIDC_NAME_STALE")" || fail "e3: authorize"
  C=$(stepup "$OIDC_NAME_STALE" "$CODE" "$W/r-e3.json"); R=$(reason "$W/r-e3.json")
  echo "e3 stepUpAuthCodeURL -> authn: pages=$PAGES HTTP $C $R"
  [[ "$PAGES" != sso && "$C" == 200 ]] && pass "e: stepUpAuthCodeURL (max_age) makes Keycloak re-authenticate ($PAGES) -> 200" \
    || fail "e: stepUpAuthCodeURL -> pages=$PAGES $C $R"
  "$HERE/realm.sh" loa2-max-age 0 >/dev/null && trap - EXIT
fi
fi

########################################################################
step "verdict"
if (( ${#FAILS[@]} )); then
  printf 'FAILED: %s\n' "${FAILS[@]}"
  echo "STEP-UP E2E: FAIL (${#FAILS[@]})"; exit 1
fi
echo "STEP-UP E2E: PASS"
