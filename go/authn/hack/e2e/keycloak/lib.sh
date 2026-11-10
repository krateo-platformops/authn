#!/usr/bin/env bash
# Helpers shared by stepup.sh and guard.sh: result lines, the authn calls, and a
# curl-driven Keycloak login (authorize). Source it after setting W (a work
# directory), CURL_X (extra curl args for Keycloak), AUTHN_URL, TOTP_SEED,
# REDIRECT_URI (set by the caller once /strategies is read) and FAILS=().
# shellcheck disable=SC2034,SC2154
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
