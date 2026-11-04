package restaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/outbound"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/krateo-platformops/plumbing/kubeutil"
	templatesv1 "github.com/krateo-platformops/snowplow/apis/templates/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

type RestActionContextKey string

type Response struct {
	Status map[string]interface{} `json:"status"`
}

// Resolve asks snowplow to resolve the RESTAction ref for the user whose IdP
// access token is bearerToken, and returns its .status. The token travels in
// the body of POST /call/read as extras.token (snowplow >= 1.12.28), never in
// a URL, where gateways and trace spans record it. A RESTAction reads it as
// ${ .token }, e.g. in an Authorization header.
func Resolve(ctx context.Context, ref *core.ObjectRef, bearerToken string) (map[string]interface{}, error) {
	base, _ := ctx.Value(RestActionContextKey("snowplowURL")).(string)
	if base == "" {
		return nil, errors.New("snowplow URL is not configured")
	}
	q := url.Values{}
	q.Set("apiVersion", "templates.krateo.io/v1")
	q.Set("resource", "restactions")
	q.Set("name", ref.Name)
	q.Set("namespace", ref.Namespace)

	body, err := json.Marshal(map[string]any{"extras": map[string]string{"token": bearerToken}})
	if err != nil {
		return nil, fmt.Errorf("encoding the extras: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/call/read?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for restaction call to snowplow: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	jwt, ok := xcontext.AccessToken(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve jwt token for authn")
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))

	resp, err := outbound.Client().Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request for restaction call to snowplow: %w", err)
	}
	defer resp.Body.Close()
	responseRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read snowplow's answer: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, snowplowError(resp.StatusCode, responseRaw)
	}

	var responseStruct Response
	if err := json.Unmarshal(responseRaw, &responseStruct); err != nil {
		return nil, fmt.Errorf("snowplow's answer is not a RESTAction: %v", err)
	}
	return responseStruct.Status, nil
}

// SnowplowError is snowplow's own non-200 answer to a RESTAction call: its
// status code and the reason and message of its Status body.
type SnowplowError struct {
	Code    int
	Reason  string
	Message string
}

func (e *SnowplowError) Error() string {
	return fmt.Sprintf("snowplow answered %d %s: %s", e.Code, e.Reason, e.Message)
}

func snowplowError(code int, body []byte) *SnowplowError {
	var st struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &st)
	if st.Reason == "" && st.Message == "" {
		st.Message = string(body)
	}
	return &SnowplowError{Code: code, Reason: st.Reason, Message: st.Message}
}

// LegacyResolve resolves a RESTAction written for the old shape, whose stages
// carry no ${ .token } header: it copies the RESTAction and its endpoint
// Secrets with the user's token written in as the endpoint credential, calls
// the copy, and deletes it. It is a fallback only, logged at warn by its
// callers, and is deleted once no live RESTAction needs it.
func LegacyResolve(ctx context.Context, rc *rest.Config, restaction *core.ObjectRef, email string, bearerToken string) (map[string]interface{}, error) {
	restactionCopy, err := copyRestActionWithEndpoints(ctx, rc, restaction, email, bearerToken)
	if err != nil {
		return nil, fmt.Errorf("could not resolve restaction: %v", err)
	}

	// Call the RESTAction from snowplow
	url := fmt.Sprintf(ctx.Value(RestActionContextKey("snowplowURL")).(string)+
		"/call?apiVersion=templates.krateo.io%%2Fv1&resource=restactions&name=%s&namespace=%s",
		restactionCopy.Name,
		restactionCopy.Namespace)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for restaction call to snowplow: %w", err)
	}

	jwt, ok := xcontext.AccessToken(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve jwt token for authn")
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))

	resp, err := outbound.Client().Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request for restaction call to snowplow: %w", err)
	}
	defer resp.Body.Close()
	responseRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read snowplow's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, snowplowError(resp.StatusCode, responseRaw)
	}

	var responseStruct Response
	err = json.Unmarshal(responseRaw, &responseStruct)
	if err != nil {
		return nil, fmt.Errorf("error parsing userinfo payload JSON: %v\npayload: %s", err, string(responseRaw))
	}

	err = deleteRestActionCopyWithEndpoints(ctx, rc, restactionCopy)
	if err != nil {
		return nil, fmt.Errorf("error while deleting copy of restaction and secrets: %v", err)
	}

	return responseStruct.Status, nil
}

// Make a copy of the restAction object for the current user, as well as all endpoints
func copyRestActionWithEndpoints(ctx context.Context, rc *rest.Config, restaction *core.ObjectRef, email string, bearerToken string) (*core.ObjectRef, error) {
	restactionObj, err := Get(ctx, rc, restaction)
	if err != nil {
		return nil, fmt.Errorf("could not obtain restaction object for %s %s: %w", restaction.Name, restaction.Namespace, err)
	}

	restactionObjCopy := &templatesv1.RESTAction{}
	restactionObjCopy.Name = restactionObj.Name + "-" + kubeutil.MakeDNS1123Compatible(email)
	restactionObjCopy.Namespace = restactionObj.Namespace
	restactionObjCopy.Spec = restactionObj.Spec

	for i, api := range restactionObjCopy.Spec.API {
		if api.EndpointRef != nil {
			secretSelector := &core.SecretKeySelector{Name: api.EndpointRef.Name, Namespace: api.EndpointRef.Namespace}
			restactionSecret, err := secrets.Get(ctx, rc, secretSelector)
			if err != nil {
				return nil, fmt.Errorf("could not read endpoint secret object for restaction %s %s, endpoint %s %s: %w", restaction.Name, restaction.Namespace, secretSelector.Name, secretSelector.Namespace, err)
			}

			restactionSecretCopy := &v1.Secret{}
			restactionSecretCopy.Name = restactionSecret.Name + "-" + kubeutil.MakeDNS1123Compatible(email)
			restactionSecretCopy.Namespace = restactionSecret.Namespace
			restactionSecretCopy.Data = restactionSecret.Data
			if _, ok := restactionSecretCopy.Data["token"]; !ok {
				restactionSecretCopy.StringData = make(map[string]string)
				restactionSecretCopy.StringData["token"] = bearerToken
			}

			restactionObjCopy.Spec.API[i].EndpointRef.Name = restactionSecretCopy.Name
			err = secrets.CreateOrUpdate(ctx, rc, restactionSecretCopy)
			if err != nil {
				return nil, fmt.Errorf("could not create copy of endpoint secret object for restaction %s (%s) %s, endpoint %s %s: %w", restaction.Name, restaction.Namespace, secretSelector.Name, restactionSecret.Name, secretSelector.Namespace, err)
			}
		}
	}

	err = CreateOrUpdate(ctx, rc, restactionObjCopy)
	if err != nil {
		return nil, fmt.Errorf("could not create copy of restaction object for %s (%s) %s: %w", restaction.Name, restactionObjCopy.Name, restaction.Namespace, err)
	}

	return &core.ObjectRef{Name: restactionObjCopy.Name, Namespace: restactionObjCopy.Namespace}, nil
}

// Delete the copy of the restAction object for the current user, as well as all endpoints
func deleteRestActionCopyWithEndpoints(ctx context.Context, rc *rest.Config, restaction *core.ObjectRef) error {
	restactionObj, err := Get(ctx, rc, restaction)
	if err != nil {
		return fmt.Errorf("could not obtain restaction object to delete for %s %s: %w", restaction.Name, restaction.Namespace, err)
	}

	// Delete all secret endpoints first
	deleted := make([]*core.SecretKeySelector, 0)
	for _, api := range restactionObj.Spec.API {
		if api.EndpointRef != nil {
			secretSelector := &core.SecretKeySelector{Name: api.EndpointRef.Name, Namespace: api.EndpointRef.Namespace}
			if hasSecret(deleted, secretSelector) { // The endpoint copy has already been deleted
				continue
			}
			err = secrets.Delete(ctx, rc, secretSelector)
			if err != nil {
				return fmt.Errorf("could not delete copy of endpoint secret object for restaction %s %s, endpoint %s %s: %w", restaction.Name, restaction.Namespace, secretSelector.Name, secretSelector.Namespace, err)
			}
			deleted = append(deleted, secretSelector)
		}
	}

	// Delete restaction copy
	err = Delete(ctx, rc, restaction)
	if err != nil {
		return fmt.Errorf("could not delete copy of restaction object for %s %s: %w", restaction.Name, restaction.Namespace, err)
	}

	return nil
}

func hasSecret(list []*core.SecretKeySelector, obj *core.SecretKeySelector) bool {
	for _, toCheck := range list {
		if toCheck.Name == obj.Name && toCheck.Namespace == obj.Namespace {
			return true
		}
	}
	return false
}
