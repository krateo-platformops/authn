package storage

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube"
	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/plumbing/endpoints"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	ClientCertLabel = "client-certificate-data"
	ClientKeyLabel  = "client-key-data"
	CALabel         = "certificate-authority-data"
	ProxyUrlLabel   = "proxy-url"
	ServerUrlLabel  = "server-url"

	// NotBeforeAnnotation and NotAfterAnnotation record the validity window the
	// signer actually GRANTED, which can be far shorter than the one requested
	// (see internal/helpers/kube/certinfo.go). They are the only place the real
	// expiry of a stored credential is observable without decoding the Secret.
	NotBeforeAnnotation = "authn.krateo.io/certificate-not-before"
	NotAfterAnnotation  = "authn.krateo.io/certificate-not-after"
)

// CertValidityAnnotations reports the granted validity window of a base64-PEM
// client certificate, ready to be stamped onto the Secret that stores it. An
// unparseable certificate yields no annotations rather than an error: the
// annotations are observability, never a precondition for storing a credential.
func CertValidityAnnotations(certData string) map[string]string {
	crt, err := kube.ParseCertificateBase64(certData)
	if err != nil {
		return nil
	}

	return map[string]string{
		NotBeforeAnnotation: crt.NotBefore.UTC().Format(time.RFC3339),
		NotAfterAnnotation:  crt.NotAfter.UTC().Format(time.RFC3339),
	}
}

// ClientConfigSecretName names the Secret holding username's session
// credential. The name is plumbing's endpoints.SecretName, its one
// definition, which consumers such as snowplow and core-provider share.
func ClientConfigSecretName(username string) string {
	return endpoints.SecretName(username)
}

// StepUpSecretName names the Secret holding username's short-lived step-up
// credential (#49). It ends in "-clientconfig-stepup", which no session
// Secret name can: those always end in "-clientconfig". So no username's
// session Secret can collide with another username's step-up Secret, and
// nothing that lists session credentials by the "-clientconfig" suffix picks
// one up.
func StepUpSecretName(username string) string {
	return ClientConfigSecretName(username) + "-stepup"
}

// stepUpSuffix ends every StepUpSecretName and no session Secret name.
const stepUpSuffix = endpoints.ClientConfigSuffix + "-stepup"

// IsStepUpSecretName reports whether a Secret name is a step-up credential's.
func IsStepUpSecretName(name string) bool {
	return strings.HasSuffix(name, stepUpSuffix) && len(name) > len(stepUpSuffix)
}

type AuthInfo struct {
	Server   string `json:"server"`
	ProxyURL string `json:"proxy-url,omitempty"`
	CAData   string `json:"certificate-authority-data"`
	CertData string `json:"client-certificate-data"`
	KeyData  string `json:"client-key-data"`

	// Strategy is the login strategy that issued this credential. It is
	// recorded as an annotation on the Secret, never in the kubeconfig.
	Strategy Strategy `json:"-"`

	// Claim, when set, is recorded as ClaimAnnotation: the identity this
	// username was issued to (EncodeClaim).
	Claim string `json:"-"`

	// StepUp stores the credential as the user's step-up credential
	// (StepUpSecretName) instead of their session credential.
	StepUp bool `json:"-"`

	// Owner, when set, becomes the Secret's only ownerReference, so the
	// Kubernetes garbage collector deletes the credential once its owner is
	// gone. A service identity's Secret is owned by its ServiceAccount mapping.
	// It must name an object in the operator namespace by its current
	// UID: an owner the collector can't find makes it delete the Secret.
	Owner *metav1.OwnerReference `json:"-"`
}

// AuthInfoStorage stores issued credentials. authn never reads one back over
// HTTP: the Secrets are read in-cluster, under RBAC.
type AuthInfoStorage interface {
	// Put stores nfo and reports the write. On an error, Written still names
	// the Secret and, when a request was sent, its verb and the apiserver's
	// status code.
	Put(name string, nfo *AuthInfo) (Written, error)
}

// Written is one credential write: the Secret, the verb that was sent for it,
// and the apiserver's answer (AUDIT-4: an audit record names the object authn
// wrote and the verb it sent). Names only, never data.
type Written struct {
	Namespace string
	Name      string
	// UID and ResourceVersion are the stored Secret's, empty when nothing was
	// stored.
	UID             string
	ResourceVersion string
	// Verb is "create" or "update", the request that stored the Secret or
	// failed to. An existing Secret is first answered 409 to its create; that
	// is a step, not the write, so the verb is update. Empty when nothing was
	// sent.
	Verb string
	// StatusCode is the apiserver's HTTP status for that request, 0 when no
	// response arrived.
	StatusCode int
}

func Default(rc *rest.Config) AuthInfoStorage {
	return &secretStore{rc: rc}
}

var _ AuthInfoStorage = (*secretStore)(nil)

type secretStore struct {
	rc *rest.Config
}

func (st *secretStore) Put(name string, nfo *AuthInfo) (Written, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return Written{}, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	sec := corev1.Secret{}
	if nfo.StepUp {
		sec.SetName(StepUpSecretName(name))
	} else {
		sec.SetName(ClientConfigSecretName(name))
	}
	sec.SetNamespace(ns)
	w := Written{Namespace: ns, Name: sec.Name}
	identity, err := IdentityAnnotations(nfo.Strategy, nfo.CertData)
	if err != nil {
		return w, err
	}
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
	sec.SetAnnotations(annotations)
	if nfo.Owner != nil {
		sec.SetOwnerReferences([]metav1.OwnerReference{*nfo.Owner})
	}
	sec.StringData = map[string]string{
		CALabel:         nfo.CAData,
		ClientCertLabel: nfo.CertData,
		ClientKeyLabel:  nfo.KeyData,
		ServerUrlLabel:  nfo.Server,
		ProxyUrlLabel:   nfo.ProxyURL,
	}

	// The Secret is named after its user, and so are the apiserver's errors
	// about it: each one returned is wrapped to name neither (kerr).
	code, err := secrets.Create(context.TODO(), st.rc, &sec)
	if err == nil {
		return written(w, "create", code, &sec), nil
	}

	if !errors.IsAlreadyExists(err) {
		return written(w, "create", code, nil), kerr.Wrap("creating the credential Secret", err)
	}

	// The Secret exists. If it is claimed by another identity, this write would
	// hand that identity's name to this one: two first logins of the same new
	// name can both pass the name guard, and only one may be stored.
	if nfo.Claim != "" {
		have, err := secrets.Get(context.TODO(), st.rc, &core.SecretKeySelector{Name: sec.Name, Namespace: ns})
		if err != nil {
			return w, kerr.Wrap("reading the existing credential Secret", err)
		}
		c := have.GetAnnotations()[ClaimAnnotation]
		if c != "" && c != nfo.Claim {
			// Nothing written; the update this login would have sent is its verb.
			w.Verb = "update"
			return w, fmt.Errorf("%w: the claim on the credential Secret belongs to another identity", ErrClaimedByAnother)
		}
		if c == "" && !endpoints.OwnsSecret(have, name) {
			// A Secret written before claims existed whose certificate was
			// issued to another name: the derived name aliases two usernames
			// (john.doe and johndoe), and this write would replace the other
			// one's credential.
			w.Verb = "update"
			return w, fmt.Errorf("%w: the credential Secret holds a certificate issued to another name", ErrHeldByAnother)
		}
	}

	code, err = secrets.Update(context.TODO(), st.rc, &sec)
	if err != nil {
		return written(w, "update", code, nil), kerr.Wrap("updating the credential Secret", err)
	}
	return written(w, "update", code, &sec), nil
}

// written completes w with the request sent and, when it stored one, the
// stored Secret's uid and resourceVersion.
func written(w Written, verb string, code int, stored *corev1.Secret) Written {
	w.Verb, w.StatusCode = verb, code
	if stored != nil {
		w.UID, w.ResourceVersion = string(stored.UID), stored.ResourceVersion
	}
	return w
}

// ErrClaimedByAnother: Put found the Secret claimed by another identity, and
// stored nothing.
var ErrClaimedByAnother = stderrors.New("the username is claimed by another identity")

// ErrHeldByAnother: Put found an unclaimed Secret, written before claims
// existed, whose certificate was issued to another name, and wrote nothing.
var ErrHeldByAnother = stderrors.New("the username's Secret holds another name's credential")
