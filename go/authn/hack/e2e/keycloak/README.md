# Step-up and name-guard e2e against a real Keycloak

These scripts test authn's step-up (`POST /oidc/stepup`) and its name guard against a real Keycloak. They check
the `acr` and `auth_time` claims Keycloak actually issues, which a mock IdP can't show.

| Script | What it does | Needs |
|---|---|---|
| `realm.sh` | Sets up the realm through the admin API. It is idempotent and works on an existing Keycloak. `realm.sh loa2-max-age <s>` changes only the LoA-2 condition. | bash, curl, jq |
| `stepup.sh` | Drives Keycloak's login pages with curl, starting from the URLs authn's `/strategies` advertises. It posts the codes to authn and checks the answers. | bash ≥ 4.4, curl, jq, openssl, od/sed/awk/base64 (kubectl only with `KUBECTL_CHECKS=1`) |
| `cluster.sh` | The harness on an existing cluster (`KUBECONFIG`): authn from its helm chart (a published release, or a local chart), Keycloak, OIDCConfigs in `NS`, then the two scripts above. | kubectl, helm, plus the above |
| `kind.sh` | A kind cluster and authn built from `REF`, then `cluster.sh` on it. | git, docker, kind, plus the above |
| `guard.sh` | The name guard against the same Keycloak and apiserver: a name a ClusterRoleBinding names as a User, the same name re-created in Keycloak with a new `sub`, a `system:` group, a reserved name. `cluster.sh` runs it after `stepup.sh`. It creates and deletes the ClusterRoleBinding `guard-e2e-bound`. | kubectl, plus the above |

The TOTP codes are computed with `openssl dgst -mac HMAC`, so python isn't needed.

## On kind

```sh
go/authn/hack/e2e/keycloak/kind.sh                # authn at HEAD; the cluster is deleted at the end
REF=some-branch KEEP=1 go/authn/hack/e2e/keycloak/kind.sh
SKIP=f go/authn/hack/e2e/keycloak/kind.sh         # skip the step-up sweep check (about 20 minutes)
SKIP="d e f" go/authn/hack/e2e/keycloak/kind.sh   # also skip the two scenarios that wait 75s each
```

Scenario f waits for a real step-up certificate to expire and for authn's sweep to delete it,
so a full run takes about 15–20 minutes longer. Skip it with `SKIP=f` unless you are working on
the sweep or on step-up credentials.

Keycloak gets `KC_HOSTNAME=http://keycloak.<NS>.svc:8080`, so its issuer is the
in-cluster URL. The script reaches that same URL through a port-forward with
`curl --connect-to` (`KC_CURL_ARGS`). The Host header, cookies and issuer are therefore the
ones authn sees, and issuer validation stays on.

## On an existing cluster (GKE, ...), against a published release

```sh
KUBECONFIG=<file> NS=authn-e2e AUTHN_VERSION=0.31.1 go/authn/hack/e2e/keycloak/cluster.sh
KUBECONFIG=<file> NS=authn-e2e AUTHN_VERSION=0.31.1 UNINSTALL=1 SKIP=f go/authn/hack/e2e/keycloak/cluster.sh
```

`cluster.sh` installs everything in `NS`: the published `authn` chart, Keycloak (pulled
from quay.io), the OIDCConfigs and the user Secrets. It applies the CRDs of the
`authn-crds` chart at the same version and never deletes them. Besides `NS`, the chart
creates ClusterRoles and ClusterRoleBindings suffixed with `NS`, and authn creates CSRs, so
several runs can share a cluster in different namespaces. `AUTHN_IMAGE_DIGEST=sha256:…`
makes it fail unless the running pod has that image. `UNINSTALL=1` runs `helm uninstall`
and deletes `NS` at the end. `KUBECONFIG` is required, so the script never installs into
your default context by accident.

## In a cluster (a pod with curl)

Run `realm.sh` once, or set the realm up by hand as described below. Create the OIDCConfigs
on the same Keycloak client:
- One under test, e.g. `stepUp: {acrValues: [gold], maxAge: 5m}`.
- One with a short `maxAge` (60s) for scenarios d and e. Otherwise they wait `maxAge`+15s each.
- One with `ttl: 10m` (the CSR API's minimum) for scenario f. Otherwise f waits for the default
  15m TTL.

Keycloak's issuer, as `discoveryURL` reaches it, must be the URL the pod uses for Keycloak.
Then run `stepup.sh` in a pod (for example alpine with `apk add bash curl jq openssl`), with
the secrets taken from a Secret through `envFrom`:

| Env | Example | |
|---|---|---|
| `AUTHN_URL` | `http://authn.krateo-system.svc:8082` | required |
| `OIDC_NAME` | `keycloak` | the OIDCConfig under test |
| `OIDC_NAME_STALE` | `keycloak-stale` | same client, short `maxAge`; defaults to `OIDC_NAME` |
| `TEST_USER`, `TEST_PASSWORD`, `TOTP_SEED` | `alice`, … | the user `realm.sh` created; `TOTP_SEED` is the raw key Keycloak stores |
| `CLIENT_ID`, `CLIENT_SECRET` | `portal`, … | optional: print the ID-token claims (the code exchange is done by the script) |
| `KC_URL`, `KC_ADMIN_USER`, `KC_ADMIN_PASSWORD`, `KC_ADMIN_REALM`, `REALM` | | optional: enable scenario e, which changes the LoA-2 max age and restores 0 |
| `KUBECTL_CHECKS`, `AUTHN_NAMESPACE` | `1`, `krateo-system` | optional: check the Secrets (needs `get secrets` there); f needs it |
| `OIDC_NAME_SWEEP` | `keycloak-sweep` | f: same client, `stepUp.ttl: 10m`; defaults to `OIDC_NAME` |
| `SWEEP_REWRITE_USER` | `bob` | f: a second user (run `realm.sh` with `TEST_USER=bob`; same password and seed) for the rewrite check; skipped when unset |
| `AUTHN_SELECTOR` | `app.kubernetes.io/name=authn` | f: the authn pods whose logs are searched for the sweep (needs `get pods/log`) |
| `KC_CURL_ARGS` | empty | extra curl args for Keycloak; empty in a cluster |
| `SKIP`, `WORKDIR` | `"d e f"` | |

This is how it was validated on kind: a pod with only bash, curl, jq and openssl, no service
account token, and no `--connect-to`.

```sh
kubectl -n krateo-system create configmap e2e-keycloak --from-file=realm.sh --from-file=stepup.sh
kubectl -n krateo-system create secret generic e2e-keycloak-env --from-env-file=e2e.env   # the env above
```

```yaml
apiVersion: v1
kind: Pod
metadata: { name: e2e-stepup, namespace: krateo-system }
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  containers:
  - name: e2e
    image: alpine:3.20
    command: ["sh", "-c", "apk add -q --no-cache bash curl jq openssl && bash /e2e/stepup.sh"]
    envFrom: [{ secretRef: { name: e2e-keycloak-env } }]
    volumeMounts: [{ name: e2e, mountPath: /e2e }]
  volumes: [{ name: e2e, configMap: { name: e2e-keycloak, defaultMode: 0755 } }]
```

`kubectl logs -f e2e-stepup` ends with `STEP-UP E2E: PASS` (exit 0) or the list of failures (exit 1).

`realm.sh` takes `KC_URL`, `KC_ADMIN_*`, `REALM`, `CLIENT_ID`, `CLIENT_SECRET`,
`REDIRECT_URI` (the OIDCConfig's `redirectURI`), `TEST_USER`, `TEST_PASSWORD`, `TOTP_SEED`,
`TEST_GROUP`, `ACR_LOA_MAP` and `LOA2_MAX_AGE`. It deletes and recreates the test user
every run, so use a dedicated user. The redirect target never has to exist: the scripts
read the code from the `Location` header.

## Scenarios

| | |
|---|---|
| strategies | `stepUpAuthCodeURL` carries `acr_values` and `max_age` and keeps the login parameters; `state` is base64url (no NUL) |
| probe | the claims Keycloak issues for a login (`acr=silver`) and a step-up (`acr=gold`) |
| a | login via `authCodeURL` → `/oidc/login` 200, session JWT without `krateo:loa:2` |
| c | a login code → `/oidc/stepup` 403 `InsufficientAssurance` |
| b | `stepUpAuthCodeURL` → OTP → `/oidc/stepup` 200: JWT and cert carry `krateo:loa:2`, JWT exp ≤ cert notAfter, session Secret untouched |
| d | session older than `maxAge`, LoA-2 max age 0: `acr_values` alone asks only for the OTP and returns a fresh `auth_time` → 200; `stepUpAuthCodeURL` → 200 |
| e | LoA-2 max age 300s: `acr_values` alone is answered from SSO with the old `auth_time` → 403 `StaleAuthentication`; `stepUpAuthCodeURL` (its `max_age`) makes Keycloak re-authenticate → 200 |
| f | the sweep (authn#66), about 20 minutes: a step-up with `ttl: 10m`; at the cert's notAfter+4m the step-up Secret is still there (5m grace); by notAfter+11m it is gone and authn logged `step-up sweep: expired credential deleted` for it, at or after notAfter+5m; the session Secret's resourceVersion and data are unchanged. With `SWEEP_REWRITE_USER`, that user steps up again 1m after the first cert expired: the rewritten Secret is still there at the first notAfter+11m, after a sweep pass that saw the first cert past the grace |

d and e drop `max_age` from `stepUpAuthCodeURL` on purpose, to show what it prevents. f reads
notAfter from the certificate: signers backdate notBefore (GKE's by 2m), so it is not notBefore+ttl.

## The Keycloak configuration

- **Realm → General → ACR to LoA Mapping** (`acr.loa.map`): `silver` → 1, `gold` → 2. Keycloak
  then puts the name in `acr` (`gold`), not the level. `spec.stepUp.acrValues` must use these
  names.
- **Authentication → flow `browser-stepup`**, bound to the client as its browser-flow override.
  It follows the Keycloak guide "Creating a browser login flow with step-up mechanism":
  - Cookie: Alternative
  - a generic subflow: Alternative, containing two Conditional subflows:
    - `loa1`: *Condition - Level of Authentication* (level 1, max age 36000), then
      *Username Password Form*, both Required
    - `loa2`: *Condition - Level of Authentication* (level 2, **max age 0**), then
      *OTP Form*, both Required
- **Client:** confidential, standard flow only, redirect URI = the OIDCConfig's
  `redirectURI`. The default `acr` client scope ("acr loa level" mapper) must be one of its
  default scopes; it is by default. `auth_time` needs no setup. Add a *Group Membership*
  mapper with claim `groups` and full path off: authn reads the groups from the ID token.
- **User:** password and OTP, plus email, first name and last name. Without those, Keycloak
  shows an update-profile page.

## The two traps

1. **Send `max_age` on every step-up request**, not only after a `StaleAuthentication`.
   `stepUpAuthCodeURL` already does, so the portal must redirect to it as is. With
   `acr_values` alone, Keycloak may answer from the SSO session with the old `auth_time`
   (scenario e), and authn refuses it.
2. **The LoA-2 condition's max age must be ≤ authn's `spec.stepUp.maxAge`**; 0 is best. With
   0, every step-up asks for the OTP and `auth_time` is the OTP time. A longer LoA-2 max age
   lets Keycloak return `acr=gold` from SSO without the OTP. Only `max_age` then keeps
   `auth_time` fresh.
