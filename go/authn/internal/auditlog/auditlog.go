// Package auditlog writes authn's audit records (AUDIT-4, authn#119): one per
// credential authn writes for a verified caller, and one per token /delegate
// issues. Records go to the audit LoggerProvider and nowhere else; their
// attributes carry identity on purpose, so they never reach a span or a log line.
package auditlog

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"go.opentelemetry.io/otel/log"
)

// The instrumentation scopes, as audit's schema lists authn's populations.
const (
	ScopeRequest    = "github.com/krateo-platformops/authn/audit"
	ScopeController = "github.com/krateo-platformops/authn/audit/controller"
)

// The krateo.action literals.
const (
	ActionDelegate = "authn.delegate"
	actionLogin    = "authn.login."
	ActionStepUp   = "authn.stepup.oidc"
)

// LoginAction is the krateo.action of a login with strategy.
func LoginAction(strategy storage.Strategy) string { return actionLogin + string(strategy) }

// The record bodies: a closed set, never an error's text or an upstream answer.
const (
	msgIssued  = "credential issued"
	msgRefused = "credential refused"
	msgFailed  = "credential issuance failed"
)

// Recorder writes authn's request records. A nil Recorder, or one built
// without a LoggerProvider, writes nothing.
type Recorder struct {
	req     *audit.Emitter
	preview PreviewSource
	naming  storage.Naming
}

// WithNaming returns a copy of the Recorder that names a checked username's
// Secret as naming does (storage.Naming). The default is the legacy naming.
func (r *Recorder) WithNaming(n storage.Naming) *Recorder {
	if r == nil {
		return nil
	}
	c := *r
	c.naming = n
	return &c
}

// PreviewSource reports whether namespace is a preview sandbox, as the
// apiserver says (its Namespace's krateo.io/purpose label). ok is false when
// it could not be read.
type PreviewSource func(ctx context.Context, namespace string) (sandbox, ok bool)

// New builds the Recorder. lp nil (the logs pipeline is off) makes every
// record a no-op.
func New(lp log.LoggerProvider, preview PreviewSource) *Recorder {
	if lp == nil {
		return &Recorder{}
	}
	return &Recorder{
		req:     audit.New(lp.Logger(ScopeRequest), audit.WithWriter(audit.WriterRequest)),
		preview: preview,
	}
}

// Issuance records one verified identity's credential write: the Secret
// written (or, refused or failed before the write, the one that would have
// been), the verb sent, and the apiserver's answer. err is what Generate
// returned. It is called once per verified login, after Generate, whatever the
// outcome; a caller refused before verification records nothing. The record
// carries issued.Claim, the verified identity's claim, as
// krateo.audit.identity.claim (audit v0.15.0; snowplow's ruling: the claim of
// the identity verified on the record, and nothing else).
func (r *Recorder) Issuance(req *http.Request, action string, user userinfo.Info, principal jwtutil.Principal, issued config.Issued, err error) {
	if r == nil || r.req == nil {
		return
	}
	ctx := req.Context()
	ev := audit.Event{
		UserName:  user.GetUserName(),
		UserRoles: user.GetGroups(),
		Action:    action,
		Outcome:   audit.OutcomeSuccess,
		Message:   msgIssued,
		// Emit writes it only in format identity_claim.
		IdentityClaim: issued.Claim,
	}
	if c, ok := audit.ParseClaim(string(principal)); ok {
		ev.ActorClass = c
	}
	switch {
	case err == nil:
	case config.RefusalOf(err) != "":
		// authn refused before asking the apiserver: no status code, which in
		// schema v1 is the authority's answer.
		ev.Outcome, ev.Message = audit.OutcomeDenied, msgRefused
		ev.DenialReason = denialReasons[config.RefusalOf(err)]
	default:
		ev.Outcome, ev.Message = audit.OutcomeFailure, msgFailed
	}
	r.secretTarget(ctx, &ev, issued.Secret, ev.Outcome != audit.OutcomeDenied)
	r.request(req, &ev, queryParams[action])
	r.req.Emit(ctx, ev)
}

// secretTarget names the credential Secret as the record's object.
func (r *Recorder) secretTarget(ctx context.Context, ev *audit.Event, w storage.Written, withStatus bool) {
	if w.Namespace == "" && w.Name == "" {
		// Nothing about the Secret is known: the record names no object.
		return
	}
	ev.Namespace, ev.Version, ev.Resource, ev.Kind = w.Namespace, "v1", "secrets", "Secret"
	// An identity with no username names no Secret: the record names the
	// resource without its name (schema v1, name_missing), and its verb and
	// method are marked missing.
	ev.ObjectName = w.Name
	ev.Verb, ev.HTTPMethod = w.Verb, methodOf(w.Verb)
	if withStatus {
		ev.StatusCode = w.StatusCode
		ev.ObjectUID, ev.ObjectResourceVersion = w.UID, w.ResourceVersion
	}
	// A denial wrote nothing, so it names no stored object's uid or version,
	// whatever the caller handed in.
	ev.Preview = r.previewOf(ctx, w.Namespace)
}

func (r *Recorder) previewOf(ctx context.Context, namespace string) audit.Preview {
	return previewOf(r.preview, ctx, namespace)
}

func previewOf(preview PreviewSource, ctx context.Context, namespace string) audit.Preview {
	if preview == nil || namespace == "" {
		return audit.PreviewUnknown
	}
	sandbox, ok := preview(ctx, namespace)
	if !ok {
		return audit.PreviewUnknown
	}
	return audit.PreviewOf(sandbox)
}

// methodOf is the HTTP method authn sends for verb.
func methodOf(verb string) string {
	switch verb {
	case "create":
		return http.MethodPost
	case "update":
		return http.MethodPut
	case "patch":
		return http.MethodPatch
	case "delete":
		return http.MethodDelete
	case "get":
		return http.MethodGet
	}
	return ""
}

// queryParams lists, per action, the query parameters its route reads; the
// record keeps those and drops every other, so nothing a client adds to the
// query (a token, an OAuth or OIDC callback's code and state) reaches it. An
// action not listed keeps none.
var queryParams = map[string][]string{
	LoginAction(storage.StrategyBasic): {"d"},
	LoginAction(storage.StrategyLDAP):  {"name"},
	LoginAction(storage.StrategyOAuth): {"name"},
	LoginAction(storage.StrategyOIDC):  {"name"},
	ActionStepUp:                       {"name"},
}

// request copies the inbound request's facts. keep names the query parameters
// the record may carry; the rest of the query is dropped.
func (r *Recorder) request(req *http.Request, ev *audit.Event, keep []string) {
	uri := req.URL.EscapedPath()
	if len(keep) > 0 {
		in, kept := req.URL.Query(), url.Values{}
		for _, k := range keep {
			if vs, ok := in[k]; ok {
				kept[k] = vs
			}
		}
		if q := kept.Encode(); q != "" {
			uri += "?" + q
		}
	}
	ev.RequestURI = uri
	ev.SourceIPs = sourceIPs(req)
	ev.UserAgent = req.UserAgent()
	ev.ReceivedTime = ReceivedAt(req.Context())
}

// sourceIPs is the X-Forwarded-For entries, then the peer.
func sourceIPs(req *http.Request) []string {
	var out []string
	for _, h := range req.Header.Values("X-Forwarded-For") {
		for _, ip := range strings.Split(h, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				out = append(out, ip)
			}
		}
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil && host != "" {
		out = append(out, host)
	} else if req.RemoteAddr != "" {
		out = append(out, req.RemoteAddr)
	}
	return out
}

type receivedKey struct{}

// ReceivedAt is when Middleware received the request, zero outside it.
func ReceivedAt(ctx context.Context) time.Time {
	t, _ := ctx.Value(receivedKey{}).(time.Time)
	return t
}

// CachedPreview reads namespace's preview label through get at most once per
// ttl. A read that fails is not cached, so the next record retries.
func CachedPreview(get func(ctx context.Context, namespace string) (map[string]string, error), ttl time.Duration) PreviewSource {
	type entry struct {
		sandbox bool
		at      time.Time
	}
	var mu sync.Mutex
	cache := map[string]entry{}
	return func(ctx context.Context, namespace string) (bool, bool) {
		mu.Lock()
		e, hit := cache[namespace]
		mu.Unlock()
		if hit && time.Since(e.at) < ttl {
			return e.sandbox, true
		}
		labels, err := get(ctx, namespace)
		if err != nil {
			return false, false
		}
		e = entry{sandbox: labels[PreviewLabel] == PreviewSandbox, at: time.Now()}
		mu.Lock()
		cache[namespace] = e
		mu.Unlock()
		return e.sandbox, true
	}
}

// The Namespace label that marks a preview sandbox.
const (
	PreviewLabel   = "krateo.io/purpose"
	PreviewSandbox = "preview-sandbox"
)

// denialReasons maps each refusal to the schema's closed-set denial reason. It
// is spelled out rather than converted, so a refusal added without a schema
// value fails TestEveryRefusalHasADenialReason instead of writing an invalid
// one.
var denialReasons = map[config.Refusal]string{
	config.RefusalNameMissing:     audit.DenialReasonNameMissing,
	config.RefusalReserved:        audit.DenialReasonNameReserved,
	config.RefusalNotIssued:       audit.DenialReasonNameNotIssued,
	config.RefusalClaimed:         audit.DenialReasonNameClaimed,
	config.RefusalHeldLegacy:      audit.DenialReasonNameHeldLegacy,
	config.RefusalProvisioned:     audit.DenialReasonNameProvisioned,
	config.RefusalBound:           audit.DenialReasonNameBound,
	config.RefusalSystemGroup:     audit.DenialReasonSystemGroup,
	config.RefusalGroupNotAllowed: audit.DenialReasonGroupNotAllowed,
	config.RefusalPlatformGroup:   audit.DenialReasonPlatformGroup,
	// A step-up the verified ID token doesn't prove (authn#132, audit v0.8.0).
	config.RefusalStepUpNotEnabled:      audit.DenialReasonStepupNotEnabled,
	config.RefusalInsufficientAssurance: audit.DenialReasonInsufficientAssurance,
	config.RefusalStaleAuthentication:   audit.DenialReasonStaleAuthentication,
	// A token exchange whose subject never signed in (authn#155, audit
	// v0.15.0). No login refuses with it; /delegate's records map it too.
	config.RefusalNotSignedIn: audit.DenialReasonSubjectNotSignedIn,
}
