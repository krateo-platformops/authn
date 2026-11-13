package main

import (
	"fmt"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/plumbing/endpoints"
)

// sessionNaming is the session-Secret naming AUTHN_EXACT_USERNAMES asks for
// (authn#140), or why authn can't run under it. With exact names on, authn's
// own identity (AUTHN_USERNAME) must name its Secret exactly AND under the
// same name plumbing's signup writes it (endpoints.SecretName, the legacy
// derivation): otherwise authn would keep its own credential under a legacy
// name its readers no longer treat as its own. The default, "authn", does.
func sessionNaming(exact bool, selfUsername string) (storage.Naming, error) {
	naming := storage.Naming{Exact: exact}
	if !exact {
		return naming, nil
	}
	name, ok := endpoints.ExactSecretName(selfUsername)
	if !ok {
		return naming, fmt.Errorf("%s is on, but AUTHN_USERNAME %q can't name a Secret exactly "+
			"(a DNS-1123 subdomain of at most %d characters): choose another AUTHN_USERNAME, or turn exactUsernames off",
			storage.EnvExactUsernames, selfUsername, endpoints.MaxExactUsernameLength)
	}
	if legacy := endpoints.SecretName(selfUsername); legacy != name {
		return naming, fmt.Errorf("%s is on, but AUTHN_USERNAME %q has its own Secret written as %s by plumbing's signup, not %s: "+
			"choose an AUTHN_USERNAME already in lowercase [-a-z0-9] of at most 63 characters, or turn exactUsernames off",
			storage.EnvExactUsernames, selfUsername, legacy, name)
	}
	return naming, nil
}
