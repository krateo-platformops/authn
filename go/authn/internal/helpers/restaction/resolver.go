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
	"github.com/krateo-platformops/authn/internal/helpers/outbound"
	xcontext "github.com/krateo-platformops/plumbing/context"
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
