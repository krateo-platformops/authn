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
#   f           sweep (needs KUBECTL_CHECKS=1; about 20 minutes): the step-up Secret of
#               OIDC_NAME_SWEEP survives 4m past its cert's notAfter (5m grace), is gone
#               (and logged by authn) by notAfter+11m; the session Secret is untouched.
#               With SWEEP_REWRITE_USER: that user's step-up Secret, rewritten by a second
#               step-up after its first cert expired, is not deleted.
# d and e deliberately drop max_age from stepUpAuthCodeURL to show what it
# prevents. They wait maxAge+15s of OIDC_NAME_STALE, so give that OIDCConfig a
# short maxAge (kind.sh uses 60s). f waits for real expiry, so give
# OIDC_NAME_SWEEP the shortest stepUp.ttl the CSR API allows (10m).
#
# Env (required unless a default is shown):
#   AUTHN_URL                 e.g. http://authn.krateo-system.svc:8082
#   OIDC_NAME=keycloak        the OIDCConfig (with spec.stepUp) under test
#   OIDC_NAME_STALE=$OIDC_NAME   the OIDCConfig for d and e: same Keycloak client, a short stepUp.maxAge
#   TEST_USER=alice           TEST_PASSWORD             TOTP_SEED
#   KC_CURL_ARGS=             extra curl args for every Keycloak request (kind: --connect-to)
#   CLIENT_ID=portal  CLIENT_SECRET=   to print the ID-token claims (probe); skipped when unset
#   KC_ADMIN_PASSWORD=        enables scenario e (also KC_URL, KC_ADMIN_USER, KC_ADMIN_REALM, REALM: see realm.sh)
#   SKIP=                     scenarios to skip, e.g. "d e f"
#   KUBECTL_CHECKS=0          1: also check the Secrets with kubectl (needs get on Secrets in AUTHN_NAMESPACE)
#   AUTHN_NAMESPACE=krateo-system
#   OIDC_NAME_SWEEP=$OIDC_NAME   the OIDCConfig for f: same Keycloak client, stepUp.ttl 10m
#   SWEEP_REWRITE_USER=       f: a second Keycloak user (same password and TOTP seed) for the rewrite check
#   AUTHN_SELECTOR=app.kubernetes.io/name=authn   f: the authn pods whose logs carry the sweep (needs get on pods/log)
#   WORKDIR=$(mktemp -d)      cookie jars and responses
#
# Needs bash 4.4+, curl, jq, openssl (TOTP is HMAC-SHA1 via openssl dgst), and
# od, sed, awk, base64. kubectl only with KUBECTL_CHECKS=1.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
: "${AUTHN_URL:?}" "${TEST_PASSWORD:?}" "${TOTP_SEED:?}"
OIDC_NAME=${OIDC_NAME:-keycloak}
OIDC_NAME_STALE=${OIDC_NAME_STALE:-$OIDC_NAME}
OIDC_NAME_SWEEP=${OIDC_NAME_SWEEP:-$OIDC_NAME}
SWEEP_REWRITE_USER=${SWEEP_REWRITE_USER:-}
AUTHN_SELECTOR=${AUTHN_SELECTOR:-app.kubernetes.io/name=authn}
TEST_USER=${TEST_USER:-alice}
CLIENT_ID=${CLIENT_ID:-portal}
CLIENT_SECRET=${CLIENT_SECRET:-}
SKIP=${SKIP:-}
KUBECTL_CHECKS=${KUBECTL_CHECKS:-0}
AUTHN_NAMESPACE=${AUTHN_NAMESPACE:-krateo-system}
W=${WORKDIR:-$(mktemp -d)}
mkdir -p "$W"
# shellcheck disable=SC2034 # read by lib.sh (kc)
read -ra CURL_X <<<"${KC_CURL_ARGS:-}"

FAILS=()
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$HERE/lib.sh"

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
# secret_id <name>: "<uid> <resourceVersion>", empty if the Secret is gone; non-zero only on an API error.
secret_id() { kubectl -n "$AUTHN_NAMESPACE" get secret "$1" --ignore-not-found -o jsonpath='{.metadata.uid} {.metadata.resourceVersion}'; }
secret_data_hash() { kubectl -n "$AUTHN_NAMESPACE" get secret "$1" -o json | jq -S .data | openssl dgst -sha256 | awk '{print $NF}'; }
# not_after <secret>: its certificate's notAfter in epoch seconds, as the signer set it (signers backdate notBefore, so not notBefore+ttl).
not_after() { secret_cert "$1" | openssl x509 -noout -enddate | sed 's/^notAfter=//' | jq -Rr 'gsub(" +"; " ") | strptime("%b %d %H:%M:%S %Y GMT") | mktime'; }
utc() { date -u -d "@$1" +%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%H:%M:%SZ; }
sleep_until() { local d=$(( $1 - $(date +%s) )); echo "waiting ${d}s, until $(utc "$1"): $2"; (( d > 0 )) && sleep "$d"; return 0; }
# swept <secret>: authn's "expired credential deleted" lines for it, from every authn pod.
swept() {
  kubectl -n "$AUTHN_NAMESPACE" logs -l "$AUTHN_SELECTOR" --tail=-1 --max-log-requests=20 2>/dev/null \
    | jq -Rc --arg s "$1" 'fromjson? | select(.message=="step-up sweep: expired credential deleted" and .secret==$s) | {time, namespace, secret, notAfter}'
}
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
  # exp <= notAfter, compared as dates: authn caps exp at notAfter, so they are
  # often equal, and an "openssl -checkend <exp-now>" races the kubectl call.
  NA=$(not_after "$STEPUP_SECRET")
  [[ "$NA" =~ ^[0-9]+$ ]] && (( EXP <= NA )) && pass "b: JWT exp $(utc "$EXP") <= cert notAfter $(utc "$NA")" \
    || fail "b: JWT exp $EXP ($(utc "$EXP")) outlives the step-up cert (notAfter '$NA')"
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
# f: authn's step-up sweep (authn#66). The replica holding the renewal Lease
# deletes a step-up Secret once its cert has been expired for GRACE; it sweeps
# at leader start and then every 5m, so the deletion lands between notAfter+5m
# and notAfter+10m. Waiting for a real expiry is the point, hence ~20 minutes.
GRACE=300 # stepupsweep.DefaultGrace

# f_stepup <user> <jar> <label>: a step-up of <user> with OIDC_NAME_SWEEP; 0 on 200.
f_stepup() {
  local c
  TEST_USER=$1 authorize "$2" "$(stepup_url "$OIDC_NAME_SWEEP")" || { fail "$3: $1 authorize"; return 1; }
  c=$(stepup "$OIDC_NAME_SWEEP" "$CODE" "$W/r-$3.json")
  [[ "$c" == 200 ]] && pass "$3: $1 /oidc/stepup 200 ($OIDC_NAME_SWEEP, pages=$PAGES)" || { fail "$3: $1 /oidc/stepup $c $(cat "$W/r-$3.json")"; return 1; }
}

sweep_f() {
  local c now na su_id ses_rv ses_hash id gone line t="" rw=$SWEEP_REWRITE_USER rw_secret rw_na1="" rw_id1="" rw_id2="" rw_na2=""
  rw_secret=$(dns1123 "$rw")-clientconfig-stepup
  # The rewrite user goes first, so its first cert expires no later than the
  # main one: the pass that deletes the main one then also saw this user's
  # first cert past the grace, and had to keep the rewritten Secret.
  if [[ -z "$rw" ]]; then echo "SKIP f rewrite check: no SWEEP_REWRITE_USER"
  elif f_stepup "$rw" "$W/j-f-rw" f-rw1; then
    rw_id1=$(secret_id "$rw_secret"); rw_na1=$(not_after "$rw_secret")
    [[ -n "$rw_id1" && "$rw_na1" =~ ^[0-9]+$ ]] || { fail "f-rw1: could not read $rw_secret ('$rw_id1', notAfter '$rw_na1')"; rw=""; }
    [[ -n "$rw" ]] && info "f: $rw_secret uid/rv $rw_id1, cert notAfter $(utc "$rw_na1")"
  else rw=""; fi

  authorize "$W/j-f" "$(login_url "$OIDC_NAME_SWEEP")" || fail "f: login authorize"
  c=$(login "$OIDC_NAME_SWEEP" "$CODE" "$W/r-f-login.json")
  [[ "$c" == 200 ]] && pass "f: $TEST_USER /oidc/login 200 (session Secret written)" || fail "f: /oidc/login $c $(cat "$W/r-f-login.json")"
  f_stepup "$TEST_USER" "$W/j-f" f || return 0
  su_id=$(secret_id "$STEPUP_SECRET"); na=$(not_after "$STEPUP_SECRET")
  ses_rv=$(secret_rv "$SESSION_SECRET"); ses_hash=$(secret_data_hash "$SESSION_SECRET")
  [[ -n "$su_id" && "$na" =~ ^[0-9]+$ ]] || { fail "f: could not read $STEPUP_SECRET ('$su_id', notAfter '$na')"; return 0; }
  [[ -n "$ses_rv" ]] || { fail "f: no Secret $SESSION_SECRET"; return 0; }
  now=$(date +%s)
  info "f: $STEPUP_SECRET uid/rv $su_id, cert notAfter $(utc "$na") (now+$(( na - now ))s); $SESSION_SECRET rv $ses_rv, data sha256 ${ses_hash:0:16}"
  (( na - now <= 660 )) || info "f: cert notAfter is $(( na - now ))s away: $OIDC_NAME_SWEEP's stepUp.ttl is longer than 10m, f takes longer"

  if [[ -n "$rw" ]]; then
    sleep_until $(( rw_na1 + 60 )) "$rw's first cert expired 1m ago; no sweep may delete it before +${GRACE}s"
    id=$(secret_id "$rw_secret")
    [[ "$id" == "$rw_id1" ]] && pass "f: rewrite: $rw_secret untouched 1m past its notAfter ($id)" || { fail "f: rewrite: $rw_secret is '${id:-gone}' 1m past its notAfter, was $rw_id1"; rw=""; }
  fi
  if [[ -n "$rw" ]] && f_stepup "$rw" "$W/j-f-rw" f-rw2; then
    rw_id2=$(secret_id "$rw_secret"); rw_na2=$(not_after "$rw_secret")
    [[ -n "$rw_id2" && "$rw_id2" != "$rw_id1" && "$rw_na2" =~ ^[0-9]+$ ]] && (( rw_na2 > rw_na1 )) \
      && pass "f: rewrite: $rw_secret rewritten at $(utc "$(date +%s)") with a fresh cert (uid/rv $rw_id1 -> $rw_id2, notAfter $(utc "$rw_na1") -> $(utc "$rw_na2"))" \
      || { fail "f: rewrite: $rw_secret after the second step-up: '$rw_id2', notAfter '$rw_na2'"; rw=""; }
  else rw=""; fi

  sleep_until $(( na + 240 )) "notAfter+4m, inside the ${GRACE}s grace"
  now=$(date +%s); id=$(secret_id "$STEPUP_SECRET")
  [[ "$id" == "$su_id" ]] && pass "f: at $(utc "$now") (notAfter+$(( now - na ))s) $STEPUP_SECRET is still there, same uid/rv" \
    || fail "f: at notAfter+$(( now - na ))s $STEPUP_SECRET is '${id:-gone}', was $su_id"

  echo "polling every 10s until $(utc $(( na + 660 ))) (notAfter+11m) for the sweep"
  gone=""
  while :; do
    now=$(date +%s)
    if id=$(secret_id "$STEPUP_SECRET") && [[ -z "$id" ]]; then gone=$now; break; fi
    (( now >= na + 660 )) && break
    sleep 10
  done
  [[ -n "$gone" ]] && pass "f: $STEPUP_SECRET gone, seen at $(utc "$gone") (notAfter+$(( gone - na ))s)" \
    || fail "f: $STEPUP_SECRET still there at notAfter+$(( now - na ))s ($id)"
  line=$(swept "$STEPUP_SECRET" | tail -1)
  [[ -n "$line" ]] && pass "f: authn logged \"step-up sweep: expired credential deleted\" for $STEPUP_SECRET: $line" \
    || fail "f: no \"step-up sweep: expired credential deleted\" line for $STEPUP_SECRET in the logs of pods $AUTHN_SELECTOR"
  [[ -n "$line" ]] && t=$(jq -r '.time | if type=="number" then floor else (sub("\\.[0-9]+"; "") | fromdateiso8601) end' <<<"$line" 2>/dev/null)
  if [[ "$t" =~ ^[0-9]+$ ]]; then
    (( t >= na + GRACE )) && pass "f: deleted at $(utc "$t") = notAfter+$(( t - na ))s, after the ${GRACE}s grace" \
      || fail "f: deleted at $(utc "$t") = notAfter+$(( t - na ))s, inside the ${GRACE}s grace"
  elif [[ -n "$line" ]]; then info "f: no time in the log line"; fi
  [[ "$(secret_rv "$SESSION_SECRET")" == "$ses_rv" ]] && pass "f: $SESSION_SECRET resourceVersion unchanged ($ses_rv)" \
    || fail "f: $SESSION_SECRET resourceVersion $ses_rv -> '$(secret_rv "$SESSION_SECRET")'"
  [[ "$(secret_data_hash "$SESSION_SECRET")" == "$ses_hash" ]] && pass "f: $SESSION_SECRET data unchanged (sha256 ${ses_hash:0:16})" \
    || fail "f: $SESSION_SECRET data changed"

  [[ -n "$rw" ]] || return 0
  sleep_until $(( rw_na1 + 660 )) "$rw's first notAfter+11m"
  now=$(date +%s); id=$(secret_id "$rw_secret")
  [[ "$id" == "$rw_id2" ]] && pass "f: rewrite: at $(utc "$now") (first notAfter+$(( now - rw_na1 ))s) $rw_secret is still there, as rewritten ($id)" \
    || fail "f: rewrite: at first notAfter+$(( now - rw_na1 ))s $rw_secret is '${id:-gone}', expected $rw_id2"
  line=$(swept "$rw_secret")
  [[ -z "$line" ]] && pass "f: rewrite: no sweep deletion logged for $rw_secret" || fail "f: rewrite: the sweep deleted $rw_secret: $line"
  [[ "$t" =~ ^[0-9]+$ ]] && (( t >= rw_na1 + GRACE && t < rw_na2 + GRACE )) \
    && pass "f: rewrite: the sweep pass at $(utc "$t") ran with $rw's first cert past the grace (+$(( t - rw_na1 ))s) and kept the rewritten Secret" \
    || info "f: rewrite: no sweep pass seen between $(utc $(( rw_na1 + GRACE ))) and $(utc $(( rw_na2 + GRACE ))), so the check above proves less"
}

if ! skip f; then
step "f. sweep: an expired step-up Secret is deleted after the grace; the session Secret is not ($OIDC_NAME_SWEEP)"
if (( ! KUBECTL_CHECKS )); then echo "SKIP f: needs KUBECTL_CHECKS=1"
else sweep_f; fi
fi

########################################################################
step "verdict"
if (( ${#FAILS[@]} )); then
  printf 'FAILED: %s\n' "${FAILS[@]}"
  echo "STEP-UP E2E: FAIL (${#FAILS[@]})"; exit 1
fi
echo "STEP-UP E2E: PASS"
