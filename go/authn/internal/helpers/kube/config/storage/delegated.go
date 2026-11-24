package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/plumbing/endpoints"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// DelegatedSecretName names the Secret holding the credential issued with a
// delegated token for username with groups, through actor (authn#167):
// plumbing's endpoints.DelegatedSecretName, the one definition snowplow reads
// it by.
func DelegatedSecretName(username, actor string, groups []string) string {
	return endpoints.DelegatedSecretName(username, actor, groups)
}

// IsDelegatedSecretName reports whether a Secret name is a delegated
// credential's.
func IsDelegatedSecretName(name string) bool {
	return endpoints.IsDelegatedSecretName(name)
}

// errDelegatedOptions refuses an AuthInfo that asks for a delegated
// credential and something only a sign-in's credential can be.
var errDelegatedOptions = errors.New("a delegated credential is neither a step-up credential nor owned")

// putDelegated stores nfo as username's delegated credential through
// nfo.Actor. The Secret carries:
//   - the identity annotations (strategy, groups) read from the certificate,
//     and its granted validity;
//   - endpoints.UsernameAnnotation and endpoints.ActorAnnotation, whatever
//     the naming mode: a reader proves the Secret is the token's by them
//     (endpoints.CheckDelegatedCredential);
//   - the claim, when the person's has one.
//
// It carries none of the labels a session Secret does (PrincipalLabel,
// UsernameLabelLabel). The tenant policy selects sign-ins by them, and an
// actor's exchange isn't a sign-in.
//
// The Secret is replaced on every exchange through the same actor for the same
// person with the same groups, as the step-up Secret is on every step-up. The
// exchange was vouched for before it got here. Other groups are another
// Secret: a client may hold the token of one sign-in while another of the
// person's, with other groups, is exchanged (Diego, 2026-11-24). A Secret
// under the name that isn't this person's and actor's is never replaced: that
// would take a SHA-256 collision, and is refused all the same.
//
// The groups are the certificate's, which the reader's check compares with the
// token's.
func (st *secretStore) putDelegated(ns, username string, nfo *AuthInfo) (Written, error) {
	w := Written{Namespace: ns}
	if nfo.StepUp || nfo.Owner != nil {
		return w, errDelegatedOptions
	}

	identity, err := IdentityAnnotations(nfo.Strategy, nfo.CertData)
	if err != nil {
		return w, err
	}
	name := DelegatedSecretName(username, nfo.Actor, SplitGroups(identity[GroupsAnnotation]))
	w.Name = name
	annotations := CertValidityAnnotations(nfo.CertData)
	if annotations == nil {
		annotations = map[string]string{}
	}
	for k, v := range identity {
		annotations[k] = v
	}
	if nfo.Claim != "" {
		annotations[ClaimAnnotation] = nfo.Claim
	}
	annotations[UsernameAnnotation] = username
	annotations[endpoints.ActorAnnotation] = nfo.Actor

	sec := corev1.Secret{}
	sec.SetNamespace(ns)
	sec.SetName(name)
	sec.SetAnnotations(annotations)
	sec.StringData = map[string]string{
		CALabel:         nfo.CAData,
		ClientCertLabel: nfo.CertData,
		ClientKeyLabel:  nfo.KeyData,
		ServerUrlLabel:  nfo.Server,
		ProxyUrlLabel:   nfo.ProxyURL,
	}

	code, err := secrets.Create(context.TODO(), st.rc, &sec)
	if err == nil {
		return written(w, "create", code, &sec), nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return written(w, "create", code, nil), kerr.Wrap("creating the delegated credential Secret", err)
	}

	have, err := secrets.Get(context.TODO(), st.rc, &core.SecretKeySelector{Name: name, Namespace: ns})
	if err != nil {
		return w, kerr.Wrap("reading the existing delegated credential Secret", err)
	}
	if a := have.GetAnnotations(); a[UsernameAnnotation] != username || a[endpoints.ActorAnnotation] != nfo.Actor {
		w.Verb = "update"
		return w, fmt.Errorf("%w: the delegated credential Secret under this name is another person's or actor's", ErrHeldByAnother)
	}
	// Replace exactly the Secret just proven this person's and actor's: one
	// deleted and re-created in between is a conflict, never overwritten.
	sec.ResourceVersion = have.ResourceVersion
	code, err = secrets.Update(context.TODO(), st.rc, &sec)
	if err != nil {
		return written(w, "update", code, nil), kerr.Wrap("updating the delegated credential Secret", err)
	}
	return written(w, "update", code, &sec), nil
}
