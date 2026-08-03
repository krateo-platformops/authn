package restaction

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/telemetry"
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

func Resolve(ctx context.Context, rc *rest.Config, restaction *core.ObjectRef, email string, bearerToken string) (map[string]interface{}, error) {
	jsonToken, _ := json.Marshal(map[string]string{
		"token": bearerToken,
	})
	// Call the RESTAction from snowplow
	url := fmt.Sprintf(ctx.Value(RestActionContextKey("snowplowURL")).(string)+
		"/call?apiVersion=templates.krateo.io%%2Fv1&resource=restactions&name=%s&namespace=%s&extras=%s",
		restaction.Name,
		restaction.Namespace,
		jsonToken)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for restaction call to snowplow: %w", err)
	}

	jwt, ok := xcontext.AccessToken(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve jwt token for authn")
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))

	resp, err := telemetry.HTTPClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request for restaction call to snowplow: %w", err)
	}
	responseRaw, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snowplow endpoint returned a non-200 status code: %s", string(body))
	}

	var responseStruct Response
	err = json.Unmarshal(responseRaw, &responseStruct)
	if err != nil {
		return nil, fmt.Errorf("error parsing userinfo payload JSON: %v\npayload: %s", err, string(responseRaw))
	}

	return responseStruct.Status, nil
}

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

	resp, err := telemetry.HTTPClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request for restaction call to snowplow: %w", err)
	}
	responseRaw, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()

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
